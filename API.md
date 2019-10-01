# API
## Functions

<dl>
<dt><a href="#initJWTService">initJWTService(services)</a> ⇒ <code><a href="#JWTService">Promise.&lt;JWTService&gt;</a></code></dt>
<dd><p>Instantiate the JWT service</p>
</dd>
</dl>

## Typedefs

<dl>
<dt><a href="#JWTService">JWTService</a></dt>
<dd></dd>
</dl>

<a name="initJWTService"></a>

## initJWTService(services) ⇒ [<code>Promise.&lt;JWTService&gt;</code>](#JWTService)
Instantiate the JWT service

**Kind**: global function  
**Returns**: [<code>Promise.&lt;JWTService&gt;</code>](#JWTService) - A promise of the jwt service  

| Param | Type | Description |
| --- | --- | --- |
| services | <code>Object</code> | The services to inject |
| services.JWT | <code>function</code> | The JWT service configuration object |
| [services.log] | <code>function</code> | A logging function |
| [services.time] | <code>function</code> | A function returning the current timestamp |

**Example**  
```js
import initJWTService from 'jwt-service';

const jwt = await initJWTService({
  JWT: {
    secret: 'secret',
    duration: '2d',
    tolerance: '2h',
    algorithms: ['HS256'],
  },
  log: console.log.bind(console),
  time: Date.now.bind(Date),
});

const token = await jwt.sign({ my: 'payload' });
```
<a name="JWTService"></a>

## JWTService
**Kind**: global typedef  

* [JWTService](#JWTService)
    * [.sign(payload, [algorithm])](#JWTService.sign) ⇒ <code>Promise.&lt;JWTSignResult&gt;</code>
    * [.verify([token])](#JWTService.verify) ⇒ <code>Promise.&lt;Object&gt;</code>

<a name="JWTService.sign"></a>

### JWTService.sign(payload, [algorithm]) ⇒ <code>Promise.&lt;JWTSignResult&gt;</code>
Sign the given payload

**Kind**: static method of [<code>JWTService</code>](#JWTService)  
**Returns**: <code>Promise.&lt;JWTSignResult&gt;</code> - A promise to be resolved with the signed token.  

| Param | Type | Description |
| --- | --- | --- |
| payload | <code>Object</code> | The payload to sign |
| [algorithm] | <code>String</code> | The signing algorithm |

**Example**  
```js
const token = await jwt.sign({ my: 'payload' });
```
<a name="JWTService.verify"></a>

### JWTService.verify([token]) ⇒ <code>Promise.&lt;Object&gt;</code>
Verify and decode the given token

**Kind**: static method of [<code>JWTService</code>](#JWTService)  
**Returns**: <code>Promise.&lt;Object&gt;</code> - A promise to be resolved with the token payload.  

| Param | Type | Description |
| --- | --- | --- |
| [token] | <code>String</code> | The token to decode |

**Example**  
```js
const payload = await jwt.verify('my.jwt.token');
```
