
#include <signal.h>
#include <ola/Callback.h>
#include <ola/Clock.h>
#include <ola/Logging.h>
#include <ola/base/Flags.h>
#include <ola/base/Init.h>
#include <ola/base/SysExits.h>
#include <ola/io/SelectServer.h>
#include <ola/io/StdinHandler.h>
#include <ola/network/AdvancedTCPConnector.h>
#include <ola/network/TCPSocketFactory.h>
#include <ola/strings/Format.h>


#include <memory>
#include <string>
#include <vector>

#include "DiscoveryAgent.h"
#include "MasterEntry.h"

DEFINE_string(scope, "default", "The scope to use.");
DEFINE_uint16(tcp_connect_timeout, 5,
              "The time in seconds for the TCP connect");
DEFINE_uint16(tcp_retry_interval, 5,
              "The time in seconds before retring the TCP connection");

using ola::NewCallback;
using ola::NewSingleCallback;
using ola::io::SelectServer;
using ola::io::StdinHandler;
using ola::network::IPV4Address;
using ola::network::GenericSocketAddress;
using ola::network::IPV4SocketAddress;
using ola::network::TCPSocket;
using ola::strings::ToHex;
using ola::TimeInterval;
using std::auto_ptr;
using std::cout;
using std::endl;
using std::set;
using std::vector;

ola::TimeStamp GetTime() {
  ola::Clock clock;
  ola::TimeStamp now;
  clock.CurrentTime(&now);
  return now;
}

#define LOG_INFO OLA_INFO << GetTime() << " : "

class Client {
 public:
  Client()
      : m_stdin_handler(&m_ss,
                        ola::NewCallback(this, &Client::Input)),
        m_tcp_socket_factory(NewCallback(this, &Client::OnTCPConnect)),
        m_connector(&m_ss, &m_tcp_socket_factory,
                    TimeInterval(FLAGS_tcp_connect_timeout, 0)),
        m_backoff_policy(TimeInterval(FLAGS_tcp_retry_interval, 0)) {
  }

  bool Init() {
    // Start the agent.
    DiscoveryAgentFactory factory;
    DiscoveryAgentInterface::Options options;
    options.scope = FLAGS_scope.str();
    options.master_callback = NewCallback(this, &Client::MasterChanged);
    auto_ptr<DiscoveryAgentInterface> agent(factory.New(options));

    if (!agent->Start()) {
      return false;
    }

    m_discovery_agent.reset(agent.release());
    return true;
  }

  void Stop() {
    m_ss.Terminate();
  }

  void Run() {
    m_ss.Run();
  }

  // This is called within the Discovery thread.
  void MasterChanged(DiscoveryAgentInterface::MasterEvent event,
                     const MasterEntry &entry) {
    m_ss.Execute(NewSingleCallback(this, &Client::MasterEvent,
                 event, entry));
  }

  void Input(int c) {
    switch (c) {
      case 'h':
        ShowHelp();
        break;
      case 'm':
        DumpMasterState();
        break;
      case 't':
        cout << "Time: " << GetTime() << endl;
        break;
      case 'q':
        m_ss.Terminate();
        break;
      default:
        break;
    }
  }

 private:
  struct Master {
    std::string name;
    ola::network::IPV4SocketAddress address;
    uint8_t priority;
    TCPSocket *socket;
  };

  std::vector<Master> m_masters;
  ola::io::SelectServer m_ss;
  ola::io::StdinHandler m_stdin_handler;

  // Accessed by the discovery thread.
  std::auto_ptr<DiscoveryAgentInterface> m_discovery_agent;
  ola::network::TCPSocketFactory m_tcp_socket_factory;
  ola::network::AdvancedTCPConnector  m_connector;
  ola::ConstantBackoffPolicy m_backoff_policy;

  IPV4SocketAddress m_reported_master;

  void MasterEvent(DiscoveryAgentInterface::MasterEvent event,
                   MasterEntry entry) {
    UpdateMasterList(event, entry);

    uint8_t priority = 0;
    Master *preferred_master = NULL;
    vector<Master>::iterator iter = m_masters.begin();
    for (; iter != m_masters.end(); ++iter) {
      if (iter->priority > priority &&
          iter->address.Host() != IPV4Address::WildCard()) {
        preferred_master = &(*iter);
        priority = iter->priority;
      }
    }
    if (preferred_master) {
      if (preferred_master->address != m_reported_master) {
        LOG_INFO << "MASTER MISMATCH, picked " << preferred_master->address
                 << ", but reported was " << m_reported_master;
      }
    } else {
      if (m_reported_master != IPV4SocketAddress()) {
        LOG_INFO << "MASTER MISMATCH, failed to find master but reported was "
                 << m_reported_master;
      }
    }
  }

  void UpdateMasterList(DiscoveryAgentInterface::MasterEvent event,
                        const MasterEntry &entry) {
    vector<Master>::iterator iter = m_masters.begin();
    for (; iter != m_masters.end(); ++iter) {
      if (iter->name == entry.service_name) {
        if (event == DiscoveryAgentInterface::MASTER_REMOVED) {
          CloseConnectionToMaster(&*iter);
          iter = m_masters.erase(iter);
        } else {
          // Update
          if (iter->address != entry.address) {
            CloseConnectionToMaster(&*iter);
            iter->priority = entry.priority;
            iter->address = entry.address;
            OpenConnectionToMaster(&*iter);
          }
        }
        return;
      }
    }
    // not in the list.
    Master master = {
      entry.service_name,
      entry.address,
      entry.priority,
      NULL,
    };
    m_masters.push_back(master);
    OpenConnectionToMaster(&m_masters.back());
  }

  void OpenConnectionToMaster(Master *master) {
    if (master->address.Host() == IPV4Address::WildCard()) {
      return;
    }
    OLA_INFO << "Opening connection to " << master->name << " "
             << master->address;

    m_connector.AddEndpoint(master->address, &m_backoff_policy);
  }

  void CloseConnectionToMaster(Master *master) {
    if (master->address.Host() == IPV4Address::WildCard()) {
      return;
    }
    OLA_INFO << "Close connection to " << master->name << " "
             << master->address;
    if (master->socket) {
      m_ss.AddReadDescriptor(master->socket);
      master->socket->Close();
      delete master->socket;
    }

    if (master->address != IPV4SocketAddress()) {
      m_connector.Disconnect(master->address, true);
      m_connector.RemoveEndpoint(master->address);
    }
  }

  void OnTCPConnect(TCPSocket *socket) {
    GenericSocketAddress peer_address = socket->GetPeerAddress();
    OLA_INFO << "Opened new TCP connection to " << peer_address;
    if (peer_address.Family() != AF_INET) {
      OLA_WARN << "Invalid socket family";
      socket->Close();
      delete socket;
      exit(ola::EXIT_UNAVAILABLE);
    }
    IPV4SocketAddress peer_v4 = peer_address.V4Addr();

    vector<Master>::iterator iter = m_masters.begin();
    for (; iter != m_masters.end(); ++iter) {
      if (iter->address == peer_v4) {
        break;
      }
    }
    if (iter == m_masters.end()) {
      OLA_WARN << "Can't find master for " << peer_v4;
      socket->Close();
      delete socket;
    }

    if (iter->socket) {
      OLA_WARN << "Sockets collision for " << peer_v4;
      iter->socket->Close();
      delete iter->socket;
    }
    iter->socket = socket;

    socket->SetOnData(
        NewCallback(this, &Client::ReceiveTCPData, socket, peer_v4));
    socket->SetOnClose(
        NewSingleCallback(this, &Client::SocketClosed, peer_v4));
    m_ss.AddReadDescriptor(socket);
  }

  void ReceiveTCPData(TCPSocket *socket, IPV4SocketAddress peer) {
    uint8_t data;
    unsigned int length;
    if (socket->Receive(&data, sizeof(data), length)) {
      OLA_INFO << "Failed to read from " << peer;
    }

    switch (data) {
      case 'b':
        if (m_reported_master == peer) {
          OLA_INFO << peer << " is no longer reporting as master";
          m_reported_master = IPV4SocketAddress();
        }
        break;
      case 'm':
        if (m_reported_master != peer) {
          LOG_INFO << peer << " stole mastership from " << m_reported_master;
          m_reported_master = peer;
        }
        break;
      default:
        OLA_WARN << "Unknown status " << ToHex(data) << " from " << peer;
    }
  }

  void SocketClosed(IPV4SocketAddress peer) {
    OLA_INFO << "Socket to " << peer << " was closed";
    vector<Master>::iterator iter = m_masters.begin();
    for (; iter != m_masters.end(); ++iter) {
      if (iter->address == peer) {
        iter->socket->Close();
        delete iter->socket;
        iter->socket = NULL;
        m_connector.Disconnect(peer);
      }
    }
  }

  void DumpMasterState() {
    vector<Master>::iterator iter = m_masters.begin();
    cout << "--------------" << endl;
    for (; iter != m_masters.end(); ++iter) {
      cout << iter->name << " @ " << iter->address << ", priority "
           << static_cast<int>(iter->priority) << ", "
           << (iter->socket ? "connected" : " disconnected")
           << endl;
    }
    cout << "Reported Master is " << m_reported_master << endl;
    cout << "--------------" << endl;
  }

  void ShowHelp() {
    cout << "--------------" << endl;
    cout << "h - Show Help" << endl;
    cout << "m - Dump Master State" << endl;
    cout << "t - Print timestamp" << endl;
    cout << "q - Quit" << endl;
    cout << "--------------" << endl;
  }
};

Client *g_client = NULL;

static void InteruptSignal(OLA_UNUSED int signal) {
  if (g_client) {
    g_client->Stop();
  }
}

int main(int argc, char *argv[]) {
  ola::AppInit(&argc, argv, "[options]", "Dummy Master");

  Client client;
  if (!client.Init()) {
    exit(ola::EXIT_UNAVAILABLE);
  }

  g_client = &client;
  ola::InstallSignal(SIGINT, InteruptSignal);
  client.Run();
  g_client = NULL;
}
