# API
<a name="initJWT"></a>

## initJWT(services) ⇒ <code>Promise.&lt;Object&gt;</code>
Instantiate the JWT service

**Kind**: global function  
**Returns**: <code>Promise.&lt;Object&gt;</code> - A promise of the jwt service  

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
  }
  log: console.log.bind(console),
  time: Date.now.bind(Date),
});

const token = await jwt.sign({ my: 'payload' });
```

* [initJWT(services)](#initJWT) ⇒ <code>Promise.&lt;Object&gt;</code>
    * [~sign(payload, [algorithm])](#initJWT..sign) ⇒ <code>Promise.&lt;String&gt;</code>
    * [~verify([token])](#initJWT..verify) ⇒ <code>Promise.&lt;Object&gt;</code>

<a name="initJWT..sign"></a>

### initJWT~sign(payload, [algorithm]) ⇒ <code>Promise.&lt;String&gt;</code>
Sign the given payload

**Kind**: inner method of [<code>initJWT</code>](#initJWT)  
**Returns**: <code>Promise.&lt;String&gt;</code> - A promise to be resolved with the signed token.  

| Param | Type | Description |
| --- | --- | --- |
| payload | <code>Object</code> | The payload to sign |
| [algorithm] | <code>String</code> | The signing algorithm |

**Example**  
```js
const token = await jwt.sign({ my: 'payload' });
```
<a name="initJWT..verify"></a>

### initJWT~verify([token]) ⇒ <code>Promise.&lt;Object&gt;</code>
Verify and decode the given token

**Kind**: inner method of [<code>initJWT</code>](#initJWT)  
**Returns**: <code>Promise.&lt;Object&gt;</code> - A promise to be resolved with the token payload.  

| Param | Type | Description |
| --- | --- | --- |
| [token] | <code>String</code> | The token to decode |

**Example**  
```js
const payload = await jwt.decode('my.jwt.token');
```
