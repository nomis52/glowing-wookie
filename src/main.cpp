
#include <signal.h>
#include <ola/Callback.h>
#include <ola/Logging.h>
#include <ola/base/Flags.h>
#include <ola/base/Init.h>
#include <ola/base/SysExits.h>
#include <ola/io/SelectServer.h>
#include <ola/network/TCPSocket.h>
#include <ola/network/TCPSocketFactory.h>

#include <memory>

#include "DiscoveryAgent.h"
#include "MasterEntry.h"

DEFINE_int8(priority, 50, "Initial Master Priority");
DEFINE_string(listen_ip, "", "The IP Address to listen on");
DEFINE_uint16(listen_port, 0, "The port to listen on");
DEFINE_string(scope, "default", "The scope to use.");
DEFINE_default_bool(watch_masters, true, "Watch for master changes");

using ola::io::SelectServer;
using ola::network::IPV4Address;
using ola::network::IPV4SocketAddress;
using ola::network::TCPSocket;

class SelectServer *g_ss = NULL;

void OnTCPConnect(TCPSocket *socket_ptr) {
  // Just close the socket for now.
  socket_ptr->Close();
  delete socket_ptr;
}

static void InteruptSignal(OLA_UNUSED int signal) {
  if (g_ss) {
    g_ss->Terminate();
  }
}

void MasterChanged(DiscoveryAgentInterface::MasterEvent event,
                   const MasterEntry &entry) {
  OLA_INFO << "Got event "
           << (event == DiscoveryAgentInterface::MASTER_ADDED ?
               "Add / Update" : "Remove") << entry;
}

int main(int argc, char *argv[]) {
  ola::AppInit(&argc, argv, "[options]", "Dummy Master");

  IPV4Address master_ip;
  if (!FLAGS_listen_ip.str().empty() &&
      !IPV4Address::FromString(FLAGS_listen_ip, &master_ip)) {
    ola::DisplayUsage();
    exit(ola::EXIT_USAGE);
  }

  // Start the agent.
  DiscoveryAgentFactory factory;
  DiscoveryAgentInterface::Options options;
  options.scope = FLAGS_scope.str();
  if (FLAGS_watch_masters) {
    options.master_callback = ola::NewCallback(MasterChanged);
  }
  std::auto_ptr<DiscoveryAgentInterface> agent(factory.New(options));

  if (!agent->Start()) {
    exit(ola::EXIT_UNAVAILABLE);
  }

  // Setup TCP
  ola::network::TCPSocketFactory tcp_socket_factory(
      ola::NewCallback(OnTCPConnect));
  ola::network::TCPAcceptingSocket listen_socket(&tcp_socket_factory);

  const IPV4SocketAddress listen_address(master_ip, FLAGS_listen_port);
  if (!listen_socket.Listen(listen_address, 10)) {
    return false;
  }
  ola::network::GenericSocketAddress actual_adress =
    listen_socket.GetLocalAddress();
  if (actual_adress.Family() != AF_INET) {
    OLA_WARN << "Invalid socket family";
    exit(ola::EXIT_UNAVAILABLE);
  }
  OLA_INFO << "Listening on " << actual_adress;

  // Register as a master
  MasterEntry master_entry;
  master_entry.service_name = "Master";
  master_entry.address = actual_adress.V4Addr();
  master_entry.priority = FLAGS_priority;
  master_entry.scope = FLAGS_scope.str();
  agent->RegisterMaster(master_entry);

  SelectServer ss;
  g_ss = &ss;
  ola::InstallSignal(SIGINT, InteruptSignal);

  ss.AddReadDescriptor(&listen_socket);
  ss.Run();
  ss.RemoveReadDescriptor(&listen_socket);
}
