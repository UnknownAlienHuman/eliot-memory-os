## I1.13. Kernel unavailability

If Kernel is unavailable:

```text
no new Session, lease, canonical write or external Material authority is issued;
Host and Watchdog remain independently reachable where possible;
Recovery View shows build/generation/ORS/incident state only;
semantic task recovery waits for canonical access;
existing external tools are not claimed to be stopped unless enforcement is observed.
```

If the User Broker is unavailable, only user-session-bound routes are deferred or reconciled; machine/service-safe routes and canonical state remain available.

---

