# Python command line for Rest API

## Generate auth.json before use the cli
./rest.py -g

modify auth_host in auth.json

## If cli not enougth, you can modify example.json and use it as rest API input
./rest.py -f example.json

## Please use -h for cli detail.
Still have bug and please ask me to fix it.

## To get metadata address of VM
./rest.py -i hostip1 hostip2 ...
