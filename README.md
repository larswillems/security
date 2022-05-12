# **Security in Computing: Chat platform with end-to-end encryption**
The purpose of this project is to create a **secure** chat platform similar to Slack, which allows users to communicate messages in channels or as private messages. 

## Student Info
| Name         | E-mail              |
|--------------|---------------------|
| Bram Silue   | bram.silue@vub.be   |
| Lars Willems | lars.willems@vub.be |


## Table of Contents
1. [Introduction](##Introduction)
2. [How to run](##How-to-run)


## Introduction
We were provided a simple web-based Slack clone that contains the main functionality from Slack, although without any regards to security, both at client side and server side. 

The main goal of this project is to secure the implementation, by limiting what data can be read by different parties (such as other users, or the server itself) and protecting it from common exploits.


## How to run
The server for the chat platform is written in [NodeJS](https://nodejs.org/en/download/), and uses [Socket.IO](https://socket.io/docs/v4/) for communication. The front-end itself is a simple web client utilizing jQuery, Bootstrap and Socket.IO.

For the initial setup, open the `Chat` folder in your terminal and execute the following commands:

```
$ npm install
```

Next, to actually run the application, execute:

```
$ npm start
```

Finally, to use the application, click [here](https://localhost:8443).

### A note on HTTPS
On a public domain, our application would be served over HTTPS using a trusted TLS certificate provided by a Certificate Authority. However, because our app runs locally, we are forced to serve it over HTTPS using a *self-signed* certificate. Due to the certificate's self-signed nature, your browser may display a security warning or block access. 

One solution is to [install mkcert](https://github.com/FiloSottile/mkcert#installation), a tool for creating locally trusted certificates. After installation, run the following command (still in the `Chat` folder):

```
$ mkcert -cert-file cert.pem -key-file key.pem localhost
```

Now, using `npm start`, the Chat application should run without any security warnings from your browser.

