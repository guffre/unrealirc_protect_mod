# unrealirc_protect_mod
This is a module for UnrealIRCD 4.2.2. It protects a username and prevents them from being banned from the server (KLINES, conf bans, allow blocks, etc)

I am using API hooking techniques to overwrite the `Find_ban` and `Find_except` functions.
This is fragile and needs to be double-checked if you are porting this to a version that is not 4.2.2

The reason I did it this way is there are no official UnrealIRC hooks prior/during the config ban and config tkl checks. This way, the config checks are effectively "ignored", and then double-checked after NICK has been set.
