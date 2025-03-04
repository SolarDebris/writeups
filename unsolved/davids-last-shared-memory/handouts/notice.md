## David's Last Shared Memory Chall notice

1. If you're using Windows 11, enabling Test Mode and loading the driver may make snapshots unnecessary. Snapshots are primarily for those who don’t have Windows 11 and need the exact same environment as the problem setup.

2. The VM file includes a "snapshot 1" file. Reverting to snapshot 1 will return you to a state where BrainDance.sys is loaded and logged in as the user "Lucy."

3. If Snapshot Revert doesn’t work (such as on AMD or for CPUs that lack specific instruction support), log in with the "Arasaka_Admin" account, run CMD as Administrator, and enter:

```
sc start BrainDanceLoader
```
After logging out, log back in as "Lucy" and create a new snapshot. This will replicate the same environment as snapshot 1. (The password for the Arasaka_Admin account is "tmdcks0407." Looks like the admin's birthday might be April 7.)

4. The flag is located at:
```
C:\Users\Arasaka_Admin\Desktop\flag.txt
```

5. The TPM password for the VMX file (required when loading the VM, unrelated to the problem but necessary for Windows 11 security) is:
```c
i really want to stay at your house
```
6. The server’s VM instance is restored from a snapshot every 5 minutes. If you believe your exploit isn't working, try again after 5 minutes or request a ticket from the admin.

7. Please use the RDP connection only if you have "developed an exploit that works locally". Failure to follow this guideline may lead to issues.

```
connection_info: "RDP: 14.6.171.174, Username: Lucy, No password required"
```