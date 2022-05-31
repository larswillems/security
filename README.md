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
First, make sure to [download and install MongoDB](https://www.mongodb.com/docs/guides/server/install/). Then, make sure to [start MongoDB](https://www.mongodb.com/docs/manual/tutorial/manage-mongodb-processes/).

Our implementation provides two versions of the chat app. One version provides a smooth user experience but *without* persistent storage of data, which can be found in the folder called `chat-app (no-db)`. The other version *does* provide persistent storage of data using MongoDB, but comes with bugs on the client side that make for some issues with regards to displaying messages in some scenarios.

Choose the version you want to use, then, open the `Chat` folder in your terminal and execute the following commands *with root privileges*:

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

The solution suggest is to [install mkcert](https://github.com/FiloSottile/mkcert#installation), a specialized tool for creating locally trusted TLS certificates that are compliant with what browsers consider valid certificates. It stays updated to match requirements and best practices, and is cross-platform. After installation, run the following command (still in the `Chat` folder):

```
$ mkcert -cert-file cert.pem -key-file key.pem localhost
```

Now, using `npm start`, the Chat application should run without any security warnings from your browser.

