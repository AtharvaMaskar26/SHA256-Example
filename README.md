# SHA256-Example
This is a small project I created while learning Blockchain Development from Alchemy University. It is a SHA256 Encryptor that encrypts a given string. 

### Algorithm to convert a string to hash
1. Translate the string to Bytes using ``` utf8ToBytes(); ``` 
2. Hash the byte string using ```sha256(); ```

##### Note: sha256() gives an output in Uint8Array format, you might have to convert it into Hexadecimal equivalent using ```toHex();``` function

### Requirements 
To import required encryption modules:
``` npm install ethereum-cryptography```

#### Browsers don't have the ```require``` method defined, but Node.js does. With Browserify you can write code that uses require in the same way that you would use it in Node. 

#### Installing Browserify : 
```npm install -g browserify```

#### Now bundle up all the required modules like script.js into a single file called bundle.js with the command:
```browserify script.js -o bundle.js```

##### Note: You will have to repeat the above process everytime you make changes to the original script.js file  

#### Link the bundle.js file to your HTML and you are good to go
```<script src="bundle.js"></script>```



-----------------------------------------------------------
### Things to Add in future 
- [ ] Adding clear button
- [ ] Updating the UI and making it user friendly
