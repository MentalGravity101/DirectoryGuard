![DG1 0 1](https://github.com/user-attachments/assets/892bf524-c1d6-4d13-964a-efe3a3ecba7b)
![dg1 0 2](https://github.com/user-attachments/assets/f500e458-00c4-4bed-b4db-5d129d741081)

![467476370_4042821199375361_1693924073173039145_n (1)](https://github.com/user-attachments/assets/d8db5573-114a-4b1d-a798-35367ea40e99)

Key Features
1. Real-Time Monitoring Detects and logs file or directory events:
   Creation: Tracks newly created files or folders.
   Modification: Captures updates to file contents or metadata.
   Deletion: Logs removed files or directories.
   Movement: Monitors files or directories that are renamed or moved to another location.
   Supports monitoring multiple directories simultaneously.
2. Cross-Platform Compatibility
   Works on major operating systems like Windows, macOS, and Linux.
   Ensures consistent performance across platforms with minimal configuration.
3. Dual Interface: GUI and CLI
GUI:
   Intuitive interface using ttkbootstrap for a modern look and feel.
   Clearly grouped controls for starting, stopping, and managing monitored directories.
   Labels that display currently monitored directories in real-time.
   Features buttons for viewing logs, exporting/importing monitored directories, and stopping all monitoring.
CLI:

Comprehensive commands for:
   Starting directory monitoring.
   Viewing or filtering logs.
   Cleaning up old logs based on retention periods.
   Useful for power users or integration with automated scripts.
4. Logging and Event Management

Captures detailed information about each event:
Timestamp: Exact time of the event.
Source: Whether the event involves a file or a directory.
Path: Full path to the affected file or directory.
Change Type: Type of change (e.g., Created, Modified, Deleted, Moved).
Size Before/After: File size comparison for modification events.
Logs are stored in a database, ensuring durability and easy access.
Users can view logs via:
GUI TreeView: Displays logs in a structured format with filtering and search options.
CLI Commands: Output logs in a readable format or filter based on criteria like change type.

5. Import/Export Functionality
Export Directories:
Save the list of monitored directories to a file for backup or sharing.
Import Directories:
Load directories from a file and automatically add them to the active monitoring list.
Validates directory paths and avoids duplicates.
6. Robust Error Handling
Resilient to common issues like:
Permission Errors: Handles restricted access gracefully without crashing.
Threading Errors: Automatically resets the monitoring thread if stopped or interrupted.
Provides meaningful error messages and continues operation during unexpected exceptions.
7. Search and Filtering
GUI:
Search logs by keywords or criteria (e.g., timestamps, paths, change types).
Refresh logs dynamically to reflect the latest events.
CLI:
Filter logs by specific attributes (e.g., change_type=Modified).
8. Directory Management
Allows real-time addition and removal of monitored directories.
Displays a live list of all actively monitored directories in the GUI.
Prevents duplicate monitoring requests and ensures smooth operation.
9. Log Cleanup
Efficient cleanup of old logs to save disk space:
Specify retention periods (e.g., delete logs older than 30 days).
Available via both GUI and CLI.
