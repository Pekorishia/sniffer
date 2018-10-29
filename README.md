# sniffer
A sniffer for the Network Management and Security course 


#### The sender used to create and send the message trought socket was the sender.c inside this repository:
https://github.com/Barbalho12/basic_sniffer


### How to Compile:
```
gcc sender.c -o sender
gcc sniffer.c -o sniffer
```

### How to execute:
#### Terminal 1:
```
sudo ./sniffer
```
#### Terminal 2:
```
sudo ./sender interface_name dest_MAC_address dest_IP 1234 student_ID user_name # menssage type 1
sudo ./sender interface_name dest_MAC_address dest_IP 1234 student_ID           # menssage type 2
```
