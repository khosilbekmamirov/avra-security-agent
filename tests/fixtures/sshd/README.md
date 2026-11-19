# Synthetic `sshd -T` fixtures

Hand-maintained, synthetic output in OpenSSH 10.5p1's canonical `sshd -T` form, used to
test `runner/deploy/install-tunnel.sh`'s effective-settings check. They were modelled on
real 10.5p1 output but are not a capture of any machine:

- `openssh-10.5p1-T-unrestricted.txt` - a generic unrestricted user (must FAIL the check)
- `openssh-10.5p1-T-avra-tunnel.txt` - the same baseline with
  `runner/deploy/sshd-avra-tunnel.conf` applied (must PASS)
