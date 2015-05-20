
#include <ola/Logging.h>
#include <ola/base/Flags.h>
#include <ola/base/Init.h>

DEFINE_default_bool(bar, true, "Disable feature bar");

int main(int argc, char *argv[]) {
  ola::AppInit(&argc, argv, "[options]", "Foo");
  OLA_INFO << "--bar is " << FLAGS_bar;
}
