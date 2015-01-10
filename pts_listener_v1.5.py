# pts_listener.py
# Pneumatic Tube System Data Logger
# Captures transactions and events of the pneumatic tube system
# Listens on UDP port 1236 and writes to pts_logger database on localhost
# By MS Technology Solutions
# For Colombo Sales & Engineering, Inc
#
# History:
# v1.00  30-Dec-2008  Initial Release
# v1.01  22-Mar-2009  Add reception of parameter block
# v1.02  03-May-2009  Open/close connection each time due to 8 hour conn timeout
# v1.03
# v1.04  07-Jun-2010  Keep database open for 5 seconds until closing
# v1.05  21-Jan-2012  Additional and updated messages for Mainstream v500
version = 'pts_listener.py version 1.05 21-Jan-12'
#
import socket
import base64
import MySQLdb
import sys
import datetime
#import logging
#import logging.handlers
import signal
import os

def signal_handler(signal, frame):
        # print 'You pressed Ctrl+C!'
        sys.exit(0)

def ByteToHex( byteStr ):
    """
    Convert a byte string to it's hex string representation e.g. for output.
    """
    
    # Uses list comprehension which is a fractionally faster implementation than
    # the alternative, more readable, implementation below
    #   
    #    hex = []
    #    for aChar in byteStr:
    #        hex.append( "%02X " % ord( aChar ) )
    #
    #    return ''.join( hex ).strip()        

    return ''.join( [ "%02X " % ord( x ) for x in byteStr ] ).strip()

def StrToBytes( byteStr ):
	"""
	Convert a string of byte data into a byte array
	"""
	byteAry = []
	#byteAry.append(x) 
	for x in byteStr:
		byteAry.append(ord(x))
		
	return byteAry
	
def StrToInt ( byteStr ):
	"""
	Convert a string of byte data into an 2 byte integer
	"""
	return ord(byteStr[0]) + (ord(byteStr[1])*256)
	
def StrToLong ( byteStr ):
	"""
	Convert a string of byte data into a 4 byte integer
	"""
	return ord(byteStr[0]) + (ord(byteStr[1])<<8) + (ord(byteStr[2])<<16) + (ord(byteStr[3])<<24)

def StrToString ( byteStr ):
        """
        Convert a string of byte data into a proper length string
        Take data up to the embedded null
        """
        return byteStr.split("\0")[0]
	
def parseHeartbeat( byteStr ):
	"""
	Decompose UDP heartbeat packet into individual elements
	"""
	HBarray = []
	HBarray.append(ord(byteStr[0])) # system number
	#HBarray.append(ord(byteStr[1])) # device id number
	HBarray.append(ord(byteStr[2])) # device type
	HBarray.append(ord(byteStr[3])) # command
	HBarray.append(ord(byteStr[4])) # station (system) number
	#HBarray.append(ord(byteStr[5])) # sequence number
	HBarray.append(StrToLong(byteStr[6:])) # MS_TIMER
	HBarray.append(StrToLong(byteStr[10:])) # SEC_TIMER
	for x in range(12):                    # Everything else
		HBarray.append(ord(byteStr[14+x]))

	return HBarray
	
def parseTransaction( byteStr ):
	"""
	Decompose UDP transaction packet into individual elements
	"""
	HBarray = []
	HBarray.append(ord(byteStr[0])) # 0 system number
	#HBarray.append(ord(byteStr[1])) # device id number
	HBarray.append(ord(byteStr[2])) # 1 device type
	HBarray.append(ord(byteStr[3])) # 2 command
	HBarray.append(ord(byteStr[4])) # 3 station (system) number
	#HBarray.append(ord(byteStr[5])) # sequence number
	HBarray.append(StrToLong(byteStr[6:])) # 4 MS_TIMER
	HBarray.append(StrToLong(byteStr[10:])) # 5 Transaction Number
	HBarray.append(StrToLong(byteStr[14:])) # 6 Start Time (SEC)
	HBarray.append(StrToInt(byteStr[18:])) # 7 Duration
	HBarray.append(ord(byteStr[20])) # 8 Source station
	HBarray.append(ord(byteStr[21])) # 9 Dest station
	HBarray.append(ord(byteStr[22])) # 10 Status
	HBarray.append(ord(byteStr[23])) # 11 Flags
	
	return HBarray
	
def parseSecureRemoval( byteStr ):
	"""
	Decompose UDP secure removal packet into individual elements
	"""
	HBarray = []
	HBarray.append(ord(byteStr[0])) # 0 system number
	#HBarray.append(ord(byteStr[1])) # device id number
	HBarray.append(ord(byteStr[2])) # 1 device type
	HBarray.append(ord(byteStr[3])) # 2 command
	HBarray.append(ord(byteStr[4])) # 3 station (system) number
	#HBarray.append(ord(byteStr[5])) # sequence number
	HBarray.append(StrToLong(byteStr[6:])) # 4 MS_TIMER
	HBarray.append(StrToLong(byteStr[10:])) # 5 Transaction Number
	HBarray.append(StrToLong(byteStr[14:])) # 6 Secure Removal Time (SEC)
	HBarray.append(StrToLong(byteStr[18:]) + (ord(byteStr[24])<<32)) # 7 Card ID
	HBarray.append(ord(byteStr[22])) # 8 Status
	HBarray.append(ord(byteStr[23])) # 9 Flags
	
	return HBarray

def parseCardScan( byteStr ):
	"""
	Decompose UDP card scan packet into individual elements
	"""
	HBarray = []
	HBarray.append(ord(byteStr[0])) # 0 system number
	HBarray.append(ord(byteStr[1])) # 1 device id number
	HBarray.append(ord(byteStr[2])) # 2 device type
	HBarray.append(ord(byteStr[3])) # 3 command
	HBarray.append(ord(byteStr[4])) # 4 station (system) number
	HBarray.append(ord(byteStr[5])) # 5 sequence number
	HBarray.append(StrToLong(byteStr[6:])) # 6 MS_TIMER
	HBarray.append(StrToLong(byteStr[10:])) # 7 Card ID number
	HBarray.append(StrToLong(byteStr[14:])) # 8 Card Site number
	HBarray.append(ord(byteStr[18])) # 9 Authorized (0=no; 1=yes)
	HBarray.append(ord(byteStr[19])) # 10 Action taken (0=nothing; 1=door unlocked)
	HBarray.append(StrToLong(byteStr[20:])) # 11 Time of scan
	
	
	return HBarray

def parseParBlock( byteStr ):
	"""
	Decompose UDP parameter block into individual elements
	"""
	HBarray = []
	HBarray.append(ord(byteStr[0])) # 0 system number
	#HBarray.append(ord(byteStr[1])) # device id number
	HBarray.append(ord(byteStr[2])) # 1 device type
	HBarray.append(ord(byteStr[3])) # 2 command
	HBarray.append(ord(byteStr[4])) # 3 station (system) number
	#HBarray.append(ord(byteStr[5])) # sequence number
	HBarray.append(StrToLong(byteStr[6:])) # 4 MS_TIMER
	HBarray.append(ord(byteStr[10])) # 5 .sysid
	for i in range(10):
		idx=28+(i*12) # idx = position of start of names + (i* number of bytes per name)
		HBarray.append(StrToString(byteStr[idx:idx+11])) # 6..15 station name 0..9
		
	HBarray.append(ord(byteStr[281])) # 16 Card Left-3 digits
	HBarray.append(StrToLong(byteStr[282:])) # 17 Card Right-9 min
	HBarray.append(StrToLong(byteStr[286:])) # 18 Card Right-9 max
	# HBarray.append(ord(byteStr[287])) # cardNumBits
	# HBarray.append(ord(byteStr[288])) # cardSiteStart
	# HBarray.append(ord(byteStr[289])) # cardSiteLength
	# HBarray.append(ord(byteStr[290])) # cardIdStart
	# HBarray.append(ord(byteStr[291])) # cardIdLength
	# HBarray.append(ord(byteStr[292])) # disableLocks
	# HBarray.append(StrToInt(byteStr[293:])) # cardSiteCode
	
	
	return HBarray
def mydt( d ):
    """
    Calculate date based on supplied base of 1980-1-1 and d in seconds
    """
    return datetime.datetime.fromordinal(722815+d/86400)+datetime.timedelta(0,d%86400)


def insertTransactionIntoDb( dataAry, dbcursor ):
    """
    Insert transaction data array into the pts_datalog database
    """
    try:
        dbcursor.execute("INSERT INTO eventlog (TransNum, System, EventType, EventStart, "
                         "Duration, Source, Destination, Status, Flags) "
                         " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                         (dataAry[5], dataAry[0], dataAry[10], mydt(dataAry[6]), dataAry[7],
                          dataAry[8], dataAry[9], dataAry[10], dataAry[11]))

    except:
        print "\nError writing transaction to db ", sys.exc_info()[0]
        for x in dataAry:
            print x,
        print
        
    return

def updateSecureRemIntoDb( dataAry, dbcursor ):
    """
    Update transaction record with CardID in the pts_datalog database
    """
    try:
        dbcursor.execute("UPDATE eventlog SET ReceiverID = %s, ReceiveTime = %s "
                         "WHERE System = %s AND TransNum = %s AND Status = 0;",
                         (dataAry[7], mydt(dataAry[6]), dataAry[0], dataAry[5]))
        # also insert as an event, ID stored into Flags
        dbcursor.execute("INSERT INTO eventlog (TransNum, System, EventType, EventStart, "
                         "Source, Status, Flags) "
                         " VALUES (%s, %s, %s, %s, %s, %s, %s)",
                         (dataAry[5], dataAry[0], dataAry[8], mydt(dataAry[6]),
                          dataAry[3], dataAry[8], dataAry[7]))

        
    except:
        print "\nError writing secure id to db ", sys.exc_info()[0]
        for x in dataAry:
            print x,
        print
        
    return

def insertCardScanIntoDb( dataAry, dbcursor ):
    """
    Add record with CardID in the pts_datalog database
    """
    try:
        # insert as an event, ID stored into Flags
        dbcursor.execute("INSERT INTO eventlog (TransNum, System, EventType, EventStart, "
                         "Duration, Source, Destination, Status, Flags, ReceiverID, ReceiveTime) "
                         " VALUES (0, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                         (dataAry[0], dataAry[3], mydt(dataAry[11]), 0,
                          dataAry[4], 0, 0, dataAry[8], dataAry[7], mydt(dataAry[11])))
        
    except:
        print "\nError writing card scan to db ", sys.exc_info()[0]
        for x in dataAry:
            print x,
        print
        
    return

def insertParBlockIntoDb( dataAry, dbcursor ):
    """
    Insert the parameter block data into the database
    """
    try:
        # process as a transaction to ensure completeness
        dbcursor.execute("START TRANSACTION")
        # delete any existing parameter sets for this system
        dbcursor.execute("DELETE FROM station WHERE system = %s", (dataAry[0]))
        # insert the new parameter sets for this system
        for i in range(10):
           dbcursor.execute("INSERT INTO station (system, station, station_name) VALUES (%s, %s, '%s')"
                              % (dataAry[0], i, dataAry[6+i]))
                        
        # commit the transaction
        dbcursor.execute("COMMIT")
        
    except:
        dbcursor.execute("ROLLBACK")
        print "\nError writing parameters to db ", sys.exc_info()[0]
        for x in dataAry:
            print x,
        print
        
    return

def writePacketToLog( dataAry ):
    """
    Write the contents of the data array to the log file
    Uses dataAry[0] SystemNumber as part of the log file name
    """
    if (os.name=="nt"):
        filename = 'pts_' + str(dataAry[0]) + '.log'
    else:
        filename = '/var/log/pts_' + str(dataAry[0]) + '.log'
        
    try:
        f = open(filename, 'a')
        for x in dataAry:
            f.write(str(x)+',')
        f.write('-\n') # force a new line
        f.close()
        
    except:
        print "\nError writing to log file ", filename

    return

def openDbConnection( mdb ):
        """
        Opens the database connection
        """
        # setup and open a connection to the database
        #global db, cursor
        try:
                if (os.name=="nt"):
                        mdb = MySQLdb.connect(host="localhost", user="pts_logger", passwd="colombopts", db="pts_datalog")
                else:
                        mdb = MySQLdb.connect(host="localhost", user="pts_logger", passwd="colombopts", db="pts_datalog",
                                 unix_socket="/opt/lampp/var/mysql/mysql.sock")
                        
                # create a cursor
                mcursor = mdb.cursor()
                #print "Db connection opened"
                
        except:
                print "Error opening database connection: ", sys.exc_info()[0]
                raise
        
        return mcursor


# Start of Main()
def main():

    print version
    print 'MS Technology Solutions'

    # setup signaling (SIGHUP = 1), stop process with kill -1 pid
    if (os.name=="nt"):
        signal.signal(signal.SIGINT, signal_handler)
    else:
        signal.signal(signal.SIGHUP, signal_handler)

    # setup logging
    print 'pts_listener.py ', os.getpid()

    # setup and open a socket for UDP	
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        host = ''
        port = 1236
        bufsize = 1024
        #s.connect((HOST, PORT))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
    except:
        print "Error opening UDP socket: ", sys.exc_info()[0]
        raise

    # setup and open a connection to the database
    print "Opening connection"
    db = None
    cursor = openDbConnection( db)
    # execute SQL statement
    print "Executing SQL statement"
    cursor.execute("SELECT * FROM eventlog ORDER BY EventStart DESC")
    # get the resultset as a tuple
    result = cursor.fetchmany(10) # return the last 10 records
    # iterate through resultset
    for record in result:
        for x in record: print x,
        print
    cursor.close()
    # flag to control db openening and closing
    dbOpened = False
    dbCloseTime = datetime.datetime.now()
    # close database after 5 seconds
    dbCloseDelta = datetime.timedelta(seconds=5)        

    # loop forever
    while 1:
            # get an input packet
            mypack = s.recv(1024)
            #parse the packet
            #print "got a packet: %s" % mypack
            #print "Hex ", ByteToHex(mypack)
            #print "Dec ",
            #for a in StrToBytes(mypack):
            #	print "%d " % a,
            if (mypack[3]=="E"):	
                    # heartbeat message
                    if (os.name=="nt"):                  
                            print "HB ",
                    else:
                            pass
                        
                    #  for a in parseHeartbeat(mypack):
                    #          print "%d " % a,
                    # pass # do nothing for heartbeats
                  
            elif (mypack[3]=="S"):
                    # parameter block
                    print "PB ",
                    pb = parseParBlock(mypack)
                    for a in pb:
                            print a,
                    print
                    writePacketToLog(pb)
                    if (dbOpened == False):
                            cursor = openDbConnection(db)
                            dbOpened = True    
                    insertParBlockIntoDb(pb, cursor)
                    dbCloseTime = datetime.datetime.now() + dbCloseDelta
                    #cursor.close()
            elif (mypack[3]=="X"):
                    # transaction message
                    print "TX ",
                    tr = parseTransaction(mypack)
                    for a in tr:
                            print "%d " % a,
                    print
                    writePacketToLog(tr)
                    if (dbOpened == False):
                            cursor = openDbConnection(db)
                            dbOpened = True    
                    insertTransactionIntoDb(tr, cursor)
                    dbCloseTime = datetime.datetime.now() + dbCloseDelta
                    #cursor.close()
            elif (mypack[3]=="W"):
                    # secure removal message
                    print "SR ",
                    sr = parseSecureRemoval(mypack)
                    for a in sr:
                            print "%d " % a,
                    print
                    writePacketToLog(sr)
                    if (dbOpened == False):
                            cursor = openDbConnection(db)
                            dbOpened = True    
                    updateSecureRemIntoDb(sr, cursor)
                    dbCloseTime = datetime.datetime.now() + dbCloseDelta
                    #cursor.close()
            elif (mypack[3]=="V"):
                    # event message
                    print "EV ",
                    ev = parseTransaction(mypack)
                    for a in ev:
                            print "%d " % a,
                    print
                    writePacketToLog(ev)
                    if (dbOpened == False):
                            cursor = openDbConnection(db)
                            dbOpened = True    
                    insertTransactionIntoDb(ev ,cursor)
                    dbCloseTime = datetime.datetime.now() + dbCloseDelta
                    #cursor.close()
            elif (mypack[3]=="K"):
                    # card scan
                    print "CS ",
                    cs = parseCardScan(mypack)
                    for a in cs:
                            print "%d " % a,
                    print
                    writePacketToLog(cs)
                    if (dbOpened == False):
                            cursor = openDbConnection(db)
                            dbOpened = True    
                    insertCardScanIntoDb(cs ,cursor)
                    dbCloseTime = datetime.datetime.now() + dbCloseDelta

            # check if database should be closed            
            if (dbOpened and (datetime.datetime.now() > dbCloseTime)):
                    cursor.close
                    dbOpened = False
                    print "Db Closed"
            # loop forever
                    
    # shut down
    s.close()

if __name__ == "__main__":
    main()
