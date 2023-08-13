# EventLogFindCheater
Query the event log from usermode (windows) to find home-rolled modules crashing inside your game!  

Selectively looks for event IDs 1000/1001 (APPCRASH) in the event log and checks the log entries respective faulting module and host process name, and then checks the faulting module against a whitelist.   

For example: If we are running this code from CoolGame.exe and a module named "BadCode.dll" has previously thrown fatal exceptions (0xc0000005), we check if "BadCode.dll" is currently loaded. If it is loaded, we make a decision that this might be a cheating/hack program and report back to our server since there are previous event log entries telling us this module has crashed our program. And, If there are multiple crashes with different offsets from the same module, it's more likely that the faulting module is a 'cheat module'. Since there are still exceptions to this code, more information needs to be gathered about the faulting module before immediately assuming it's a cheat program. I'd like to assume the majority larger companies are already doing this for the legal's sake and to detect distributed paycheats.  

Alternatively this can be extended to work as a 'crash dump uploader', since we are reading the event log for crashes within the current processes context. 
