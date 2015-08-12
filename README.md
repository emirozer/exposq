![Screenshot](https://raw.githubusercontent.com/emirozer/exposq/master/docs/main.png)

##
This is a tiny app i made, that you would run locally on your workstation and it will dispatch [osquery](https://osquery.io/) queries to the machines under your command.
The commands are listed in the main root route of the app so you don't need to dig deep. And i really like osquery project, if you have never checked it out, you should probably take a look.


##Requirement
The only requirement is that your target machines should have osquery installed on them, thats it..

##Install

Standart Procedure

	go get github.com/emirozer/exposq

 Lets assume you are going to run exposq from your home directory(/home/user/).
After running the command above, you need to create a file called **targets.json**  in your /home/user/

Example formatting of targets.json file:

![Screenshot](https://raw.githubusercontent.com/emirozer/exposq/master/docs/targetsjson.png)

*Important Notes* : It expects a private key and you can give a key file specific to a target like the following json structure
```
{
    targets: [
        {
            "user": user,
            "ip": ip,
            "key": "key file",
        },
        {
            "user": user,
            "ip": ip
        }
    ],
    "key": "global key file"
}
```

##Usage

After that just run:

	$>exposq

Open up your browser and go 

	localhost:3000


And the main route will show you which queries you can dispatch :

![Screenshot](https://raw.githubusercontent.com/emirozer/exposq/master/docs/rootroute.png)
<br>
##Examples:
<br>



**Check if any of your machines are being used as a relay**:
![Screenshot](https://raw.githubusercontent.com/emirozer/exposq/master/docs/relay.png)

**Check if any of your machines are a victim of mitm**:
![Screenshot](https://raw.githubusercontent.com/emirozer/exposq/master/docs/mm.png)

**Check the uptime of your machines**:

![Screenshot](https://raw.githubusercontent.com/emirozer/exposq/master/docs/exposq_uptime.png)
