# slack-dash

slack-dash posts message to slack when Amazon Dash Button pushed.

## Install

You have to install libpcap before bellow.

``` sh
$ go get github.com/kechako/slack-dash
```

## Usage

``` sh
$ slack-dash -token [Slack API token] -mac-addr [Dash Button MAC Addr] ifname channel message
```
