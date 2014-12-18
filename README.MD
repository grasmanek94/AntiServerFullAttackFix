Server Full fix for SA-MP

It works. You can test it yourself with. look for a spoofer ;)

----

Installation

Linux:

    wget https://github.com/grasmanek94/AntiServerFullAttackFix/archive/master.zip
    unzip master.zip
    cd ./AntiServerFullAttackFix-master
    make AntiServerFullFix

Windows:

    Open the solution with Visual Studio 2013 (express is fine) and hit "Build Solution"

Notes:

    If your players keep timing out make sure to define

        #define REQUIRE_BYTESWAP

    This will fix issues with players losing connection to your server