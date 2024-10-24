Distributed ThinLTO (DTLTO)
===========================

DTLTO allows for the distribution of backend ThinLTO compilations 
internally as part of the link step and therefore should be usable
via any build that can use ThinLTO.

DTLTO requires the LLD linker.

ELF LLD
-------

The CLI for DTLTO is:

--thinlto-distributor=<path>
  - Specifies the file to execute as a distributor process.
  - If specified ThinLTO backend compilations will be distributed.

--thinlto-remote-opt-tool=<path>
  - Specifies the path to the tool that the distributor process will use for backend compilations.
  - Constraints on the remote opt tool: 
     - Must be able to accept -mllvm options.
     - Must be able to accept -cc1.
     - The tool invoked must match the version of LLD.

-mllvm -thinlto-distributor-arg=<arg>
 - Specifies <arg> on the command line when invoking the distributor.

-mllvm -thinlto-cc1-arg=<arg>
 - Specifies <arg> on the command line to the remote opt tool.

-mllvm options are forwarded to the remote opt tool. However, -mllvm options that imply an additional input or output file dependency are unsupported and may result in miscompilation depending on the properties of the distribution system (as such additional input/output files may not be pushed-to/fetched-from distribution system nodes correctly). If such options are required then the distributor can be modified to accept switches which specify additional input/output dependencies and `-Xdist`/`-thinlto-distributor-arg=` can be used to pass such options through to the distributor.

Any LLD LTO options that affect codegen (e.g. --lto-sample-profile=<file>) are translated to -cc1-level options.

Some -mllvm and -cc1-level options are set to try to ensure that the default LTO configuration for the remote opt tool invocations reasonably matches the default LTO configuration that is used for ThinLTO in-process backend compilations.

Some -cc1-level options that do not affect the codegen, such as diagnostic format options, are set by LLD to match what would be expected for the invoked version of LLD.
