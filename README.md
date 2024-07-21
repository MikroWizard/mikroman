
# MikroMan | MikroWizard Backend


This is the MikroWizard Backend app . 

# What is MikroWizard?

Mikrotik routers are widely used in the networking industry for their robust features and flexibility. However, managing and monitoring these routers can be a complex and time-consuming task. With MikroWizard, we aim to simplify this process and empower network administrators with a powerful yet user-friendly tool.


## Features

- Router Management
- Device grouping
- Access Management
  - groups
  - Radius server
  - Permissions
  - Forceing and Automation of Permissions and Radius
- Monitoring and Reporting
  - Radius logs
  - Syslog
  - Events
  - Software logs
  - Device Health History
  - Device BW history
  - Graphs
- Automation and Scripting
  - Batch code Execution
  - Schedule code Execution
  - Backup Schedule
- Snippets ( Batch configuration )
- User Access Management
  - Create/Delete Users
  - Access Management
  - Device Access and Permission Assignment
- Auto Deploy On Routers
  - Apply Radius configuration and Forcing
  - Apply Syslog configuration and Forcing
  - Apply User Groups and Forcing
- Activity Monitoring
- NOC dashboard - Monitoring Wall (pro)
- Radio Monitoring - Radio quality and connectivity (pro)
- Firmware Management
  - Internal Firmware Repository
  - Automatic Firmware Download from the Mikrotik website and store in Repo
  - Firmware Update Schedule (pro)
  - Firmware `safe update`
    - with `safe update` Mikrowizard will take care of updating dependencies and  packages
And Many More Features is coming :)
 
## License

[AGPL](https://www.gnu.org/licenses/agpl-3.0.html)


## Tech Stack

**Code :** Python , Bash , UWCGI 

**Database :** PostgreSQL , Redis , Redis Time Series 

Thanks to RESTPie3 from https://github.com/tomimick/restpie3

## Deployment

To deploy this project run

```bash
  Installation script is under development :) 
```

