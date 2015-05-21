
#include <signal.h>
#include <ola/Callback.h>
#include <ola/Logging.h>
#include <ola/base/Flags.h>
#include <ola/base/Init.h>
#include <ola/base/SysExits.h>
#include <ola/io/SelectServer.h>
#include <ola/network/TCPSocket.h>
#include <ola/network/InterfacePicker.h>
#include <ola/network/TCPSocketFactory.h>
#include <ola/strings/Format.h>
#include <ola/stl/STLUtils.h>

#include <memory>
#include <vector>
#include <set>
#include <string>

#include "DiscoveryAgent.h"
#include "MasterEntry.h"

DEFINE_int8(priority, 50, "Initial Master Priority");
DEFINE_string(listen_ip, "", "The IP Address to listen on");
DEFINE_uint16(listen_port, 0, "The port to listen on");
DEFINE_string(scope, "default", "The scope to use.");
DEFINE_default_bool(watch_masters, true, "Watch for master changes");

using ola::io::SelectServer;
using ola::network::Interface;
using ola::network::InterfacePicker;
using ola::network::IPV4Address;
using ola::network::IPV4SocketAddress;
using ola::network::TCPSocket;
using ola::NewCallback;
using ola::NewSingleCallback;
using ola::STLContains;
using ola::strings::ToHex;
using std::auto_ptr;
using std::set;
using std::vector;

class Server {
 public:
  explicit Server(const IPV4Address &listen_ip)
      : m_listen_ip(listen_ip),
        m_tcp_socket_factory(
            ola::NewCallback(this, &Server::OnTCPConnect)),
        m_listen_socket(&m_tcp_socket_factory),
        m_is_master(false),
        m_update_timeout(ola::thread::INVALID_TIMEOUT) {
    m_update_timeout = m_ss.RegisterRepeatingTimeout(
        1000,
        NewCallback(this, &Server::UpdateClients));
  }

  ~Server() {
    if (m_update_timeout != ola::thread::INVALID_TIMEOUT) {
      m_ss.RemoveTimeout(m_update_timeout);
      m_update_timeout = ola::thread::INVALID_TIMEOUT;
    }

    m_ss.RemoveReadDescriptor(&m_listen_socket);

    vector<TCPSocket*>::iterator iter = m_sockets.begin();
    for (; iter != m_sockets.end(); ++iter) {
      m_ss.RemoveReadDescriptor(*iter);
      (*iter)->Close();
      delete *iter;
    }
  }

  bool Init() {
    auto_ptr<InterfacePicker> picker(InterfacePicker::NewPicker());
    vector<Interface> interfaces = picker->GetInterfaces(false);
    vector<Interface>::const_iterator iter = interfaces.begin();
    for (; iter != interfaces.end(); ++iter) {
      m_local_ips.insert(iter->ip_address);
    }

    // Start the agent.
    DiscoveryAgentFactory factory;
    DiscoveryAgentInterface::Options options;
    options.scope = FLAGS_scope.str();
    if (FLAGS_watch_masters) {
      options.master_callback = ola::NewCallback(this, &Server::MasterChanged);
    }
    auto_ptr<DiscoveryAgentInterface> agent(factory.New(options));

    if (!agent->Start()) {
      return false;
    }

    const IPV4SocketAddress listen_address(m_listen_ip, FLAGS_listen_port);
    OLA_INFO << listen_address;
    if (!m_listen_socket.Listen(listen_address, 10)) {
      return false;
    }

    ola::network::GenericSocketAddress actual_address =
        m_listen_socket.GetLocalAddress();
    if (actual_address.Family() != AF_INET) {
      OLA_WARN << "Invalid socket family";
      return false;
    }
    OLA_INFO << "Listening on " << actual_address;
    m_listen_address = actual_address.V4Addr();

    // Register as a master
    MasterEntry master_entry;
    master_entry.service_name = "Master";
    master_entry.address = m_listen_address;
    master_entry.priority = FLAGS_priority;
    master_entry.scope = FLAGS_scope.str();
    agent->RegisterMaster(master_entry);

    m_ss.AddReadDescriptor(&m_listen_socket);
    m_discovery_agent.reset(agent.release());
    return true;
  }

  void Terminate() {
    m_ss.Terminate();
  }

  void Run() {
    m_ss.Run();
  }

 private:
  struct Master {
    std::string name;
    ola::network::IPV4SocketAddress address;
    uint8_t priority;
  };

  SelectServer m_ss;

  IPV4Address m_listen_ip;
  ola::network::TCPSocketFactory m_tcp_socket_factory;
  ola::network::TCPAcceptingSocket m_listen_socket;
  IPV4SocketAddress m_listen_address;
  auto_ptr<DiscoveryAgentInterface> m_discovery_agent;

  vector<TCPSocket*> m_sockets;
  set<IPV4Address> m_local_ips;
  bool m_is_master;
  ola::thread::timeout_id m_update_timeout;
  std::vector<Master> m_masters;

  void MasterChanged(DiscoveryAgentInterface::MasterEvent event,
                     const MasterEntry &entry) {
    OLA_INFO << "Got event "
             << (event == DiscoveryAgentInterface::MASTER_ADDED ?
                 "Add / Update" : "Remove") << entry;
    UpdateMasterList(event, entry);
    bool am_master = CheckIfMaster();
    if (am_master != m_is_master) {
      if (am_master) {
        OLA_INFO << "I'm now the master!";
      } else {
        OLA_INFO << "I'm no longer the master!";
      }
      m_is_master = am_master;
    }
  }

  void UpdateMasterList(DiscoveryAgentInterface::MasterEvent event,
                        const MasterEntry &entry) {
    vector<Master>::iterator iter = m_masters.begin();
    for (; iter != m_masters.end(); ++iter) {
      if (iter->name == entry.service_name) {
        if (event == DiscoveryAgentInterface::MASTER_REMOVED) {
          iter = m_masters.erase(iter);
        } else {
          iter->priority = entry.priority;
          iter->address = entry.address;
        }
        return;
      }
    }
    // not in the list.
    Master master = {
      entry.service_name,
      entry.address,
      entry.priority,
    };
    m_masters.push_back(master);
    OLA_INFO << "Added new master";
  }

  bool CheckIfMaster() {
    vector<Master>::iterator iter = m_masters.begin();
    uint8_t priority = 0;
    Master *preferred_master = NULL;
    for (; iter != m_masters.end(); ++iter) {
      if (iter->priority > priority &&
          iter->address.Host() != IPV4Address::WildCard()) {
        preferred_master = &(*iter);
        priority = iter->priority;
      }
    }
    return (preferred_master &&
            preferred_master->address.Port() == m_listen_address.Port() &&
            STLContains(m_local_ips, preferred_master->address.Host()));
  }

  void OnTCPConnect(TCPSocket *socket) {
    OLA_INFO << "New connection: " << socket;
    socket->SetOnData(
        NewCallback(this, &Server::ReceiveTCPData, socket));
    socket->SetOnClose(
        NewSingleCallback(this, &Server::SocketClosed, socket));
    m_ss.AddReadDescriptor(socket);
    m_sockets.push_back(socket);
  }

  void ReceiveTCPData(TCPSocket *socket) {
    uint8_t data;
    unsigned int length;
    if (socket->Receive(&data, sizeof(data), length)) {
      OLA_INFO << "Failed to read";
    }
    OLA_INFO << "Socket had data: " << ToHex(data);
  }

  void SocketClosed(TCPSocket *socket) {
    OLA_INFO << "Socket @ " << socket << " was closed";
    vector<TCPSocket*>::iterator iter = m_sockets.begin();
    for (; iter != m_sockets.end(); ++iter) {
      if (*iter == socket) {
        m_ss.RemoveReadDescriptor(socket);
        socket->Close();
        delete socket;
        m_sockets.erase(iter);
        break;
      }
    }
  }

  bool UpdateClients() {
    uint8_t data = m_is_master ? 'm' : 'b';
    vector<TCPSocket*>::iterator iter = m_sockets.begin();
    for (; iter != m_sockets.end(); ++iter) {
      OLA_INFO << "Sending...";
      (*iter)->Send(&data, sizeof(data));
    }
    return true;
  }
};

Server *g_server = NULL;

static void InteruptSignal(OLA_UNUSED int signal) {
  if (g_server) {
    g_server->Terminate();
  }
}

int main(int argc, char *argv[]) {
  ola::AppInit(&argc, argv, "[options]", "Dummy Master");

  IPV4Address master_ip;
  if (!FLAGS_listen_ip.str().empty() &&
      !IPV4Address::FromString(FLAGS_listen_ip, &master_ip)) {
    ola::DisplayUsage();
    exit(ola::EXIT_USAGE);
  }



  Server server(master_ip);
  if (!server.Init()) {
    exit(ola::EXIT_UNAVAILABLE);
  }

  g_server = &server;
  ola::InstallSignal(SIGINT, InteruptSignal);
  server.Run();
  g_server = NULL;
}
