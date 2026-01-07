#define NOB_IMPLEMENTATION
#define NOB_EXPERIMENTAL_DELETE_OLD
#define NOB_NO_ECHO

#include "nob.h"

#define SRC_DIR "src/"
#define MAIN_FILE SRC_DIR"main.c"
#define EXEC_DIR "exec/"
#define MAIN_EXEC EXEC_DIR"crypto"

int main(int argc, char **argv) {
    NOB_GO_REBUILD_URSELF(argc, argv);
    Nob_Cmd compile_cmd = {0};
    Nob_Cmd run_cmd = {0};

    if (!nob_mkdir_if_not_exists(SRC_DIR)) return 1;
    if (!nob_mkdir_if_not_exists(EXEC_DIR)) return 1;

    nob_cmd_append(&compile_cmd, "cc", "-O", "-ggdb", "-Wall", "-o", MAIN_EXEC, MAIN_FILE);
    nob_cmd_append(&run_cmd, "./"MAIN_EXEC);

    if (argc > 0) {
        for (int i = 1; i < argc; ++i) {
            if (argv[i][0] == '-') {
                nob_cmd_append(&compile_cmd, argv[i]);
            } else {
                nob_cmd_append(&run_cmd, argv[i]);
            }
        }
    }

    nob_cmd_run(&compile_cmd);
    nob_cmd_run(&run_cmd);
    return 0;
}
