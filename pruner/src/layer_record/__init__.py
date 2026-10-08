"""The recording pruner: records what a reference program touches and turns it into a policy.

It grants everything while it records, so it is for the instructor's reference program only,
never for an untrusted submission, and it is never reachable from phobos.sh or any layer.
"""
