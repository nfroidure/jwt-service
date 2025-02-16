[//]: # ( )
[//]: # (This file is automatically generated by the `jsarch`)
[//]: # (module. Do not change it elsewhere, changes would)
[//]: # (be overriden.)
[//]: # ( )
# Architecture Notes

## Summary

1. [JWT service](#1-jwt-service)


## 1. JWT service

This JWT service is a simple wrapper around the `jsonwebtoken` NPM
 module. It adds a level of abstraction simply providing a way to
 sign and verify JSON Web Tokens in my apps.

It also cast errors with `YError` ones and adds a tolerance for
 expired tokens so that clock drifts between instances won't be
 a problem.

 It also uses `Knifecycle` for a drop in dependency injection
 support in projects using Knifecycle.

Finally, it deal with promises which are more convenient than the
 original API.

[See in context](./src/index.ts#L64-L79)

