![Supported Python versions](https://img.shields.io/badge/python-3.6-blue.svg?style=flat-square)

# deauth
BoB11th-3rdStage-Network-deauth

## Dependencies

```[python]
sudo pip3 install -r requirements.txt 
```

## How to use

```[python]
sudo python3 airodump.py <interface> <ap mac> [<station mac> [-auth]]
```

### deauth attack
```[python]
sudo python3 airodump.py <interface> <ap mac>
```

### deauth unicast attack
```[python]
sudo python3 airodump.py <interface> <ap mac> <station mac>
```

### auth attack
```[python]
sudo python3 airodump.py <interface> <ap mac> <station mac> -auth
```
