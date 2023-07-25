# HORUS

HORUS is an integration platform that automates many of the junior analyst events at the Clemson Cyber Security Operations Center.  I wrote it during my summer there and it is still being actively used.  This public mirror has all the sensitive parts removed, including test cases.  A brief description of the tools are below.

## Duplex

We check all suspicious 2FA activity, and this tool automates most of it.  It looks for the following.
- Any fraudulent reports
- Failures not followed by successes within 30 minutes
- Impossible travel faster than 1000 kph across more than 250 km
- Failures to access the Device Management Portal

It will filter out users created in the past 6 months or users with activity only from their home state.  Users who fail these checks will be shown in order of severity with fraud reports first, and the rest based off a scoring system.

If a ticket is created for a user, they can be marked as investigated and will not show up for the next 24 hours.

## Simplex

Simplex will pull the 2FA logs and relevant HDTools information of a specified user. It does not perform checks like Duplex and only shows logs

## Visor

This small script correlates a user's VPN history.  Logs which correlate to the previous log show up as green, logs that don't show as red.  Correlation is based off source IP and MAC address.

## Sonar

This app finds the username, IP, and MAC address of any username, IP, and MAC address.  Provide it one if the three and it will try to source the other two.

## Zeppelin

Zeppelin is the (temporary) metrics tracking system for the soc. Data is stored on the `REDACTED` server via the back-end Osiris

## Apps in the works

- [ ] Refractor
