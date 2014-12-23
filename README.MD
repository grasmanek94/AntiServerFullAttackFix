Server Full fix for SA-MP

It works. You can test it yourself with. look for a spoofer ;)

----

Installation

Linux:

    wget https://github.com/grasmanek94/AntiServerFullAttackFix/archive/master.zip
    unzip master.zip
    cd ./AntiServerFullAttackFix-master
    make AntiServerFullFix

Now copy the AntiServerFullFix.so file to your server plugins folder, add it to the server.cfg on the plugins line (order doesn't matter) and your server will be protected.

Windows:

    Open the solution with Visual Studio 2013 (express is fine) and hit "Build Solution"

Now copy the Release/AntiServerFullFix.dll file to your server plugins folder, add it to the server.cfg on the plugins line (order doesn't matter) and your server will be protected.

Notes:

    If your players keep timing out make sure to define (or undefine, whichever is appropriate) [AntiServerFullAttack.cxx::88]

		//enable/disable (whichever is appropriate) this definition if you have problems with players losing randomly connection
		#define REQUIRE_BYTESWAP

    This will fix issues with players losing connection to your server

    CentOS and Fedora (RedHat based systems) Users: Your operating system enforces security protections which also prevent memory hacking (which this plugin does).
    You need to disable setenforce on your system (setenforce 0).