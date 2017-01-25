AX25 UDP Router - README.TXT

First you need to download python from http://www.python.org/

Now configure it to suit your needs. Therefore you have to edit "config.py"

Help can be displayed with
./axrouter.py --help

Debug Mode for complete packet dumps:
./axrouter.py --debug=9

[Linux]

Start the router:
./daemon start

Stop the router:
./daemon stop

Restart the router (to reload the config)
./daemon restart

[Windows]

Run
python axrouter.py
