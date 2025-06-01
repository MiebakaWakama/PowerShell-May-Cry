import os
import time
import re
import argparse
import string
import random
import threading
import traceback
import concurrent.futures
from itertools import combinations
from itertools import permutations


letters = string.ascii_lowercase
#my combination function to go back and forth on the list
#obtained from the typical combinations function
def combinations_plus(items_list, length):
    comb = combinations(items_list, length)
    #print("this is list comb:", list(comb))
    newcomb = []
    for i in list(comb):
        list_i = list(i)
        perm = permutations(list_i)
        for i in list(perm):
            newcomb.append(i)
    return list(dict.fromkeys(newcomb))


#*************************************************************
#Normalize functions of the obfuscator tools to provide
#a normalized output
#******************************************************************************************************\
#linux flavor of invoke-obfuscation
#def inob(filepath,method):
#    os.system(f"pwsh -Command \"import-module ./invoke-obfuscation; Invoke-Obfuscation -ScriptPath '{filepath}' -Command '{method}' -Quiet|Out-File obfile.ps1 \"")

#Windows flavor of invoke-obfusctaion
def inob(filepath,method,tvalue):
    os.system(f"Powershell.exe -Command \"import-module .\\invoke-obfuscation\\Invoke-Obfuscation.psd1; Invoke-Obfuscation -ScriptPath '{filepath}' -Command '{method}' -Quiet|Out-File obfile{tvalue}.ps1\"")

#invoke-stealth helper function
def instealth(filepath, technique,tvalue):
    os.system(f"Powershell.exe -Command \".\Invoke-Stealth\Invoke-Stealth.ps1 {filepath} -technique {technique} \" ")

def powerob(filepath,tvalue):
    os.system(f"Powershell.exe -Command \"python .\powerob\powerob.py obfuscate {filepath} obfile{tvalue}.ps1\" ")

def powfuscator(filepath,tvalue):
    os.system(f"Powershell.exe -Command \".\PowFuscator\PowFuscator.ps1 -infile {filepath} -outfile obfile{tvalue}.ps1 \"")

def obfuscatepy(filename,tvalue):
    os.system(f"Powershell.exe -Command \"python .\obfuscate.py {filename} \" ")
    dummyfile = filename.split(".")[0]
    if os.path.exists(f"{dummyfile} - semi-obfuscated.ps1"):
        os.remove(f"{dummyfile} - semi-obfuscated.ps1")
    if os.path.exists(f"{dummyfile} - obfuscated.ps1- name mapping.txt"):
        os.remove(f"{dummyfile} - obfuscated.ps1- name mapping.txt")
    if os.path.exists(f"{dummyfile} - obfuscated.ps1"):
        os.rename(f"{dummyfile} - obfuscated.ps1", f"obfile{tvalue}.ps1")

def goaround(filepath,tvalue):
    os.system(f"python ./GoAround/goaround.py -m obfuscate -t insertion -i {filepath}")
    if os.path.exists("output.ps1"):
        os.replace("output.ps1",f"obfile{tvalue}.ps1")

def blanket(filepath,tvalue):
    os.system(f"python ./Blanket.py -i 127.0.0.1 -p 80  -o obfile.ps1 -s {filepath}")
    if os.path.exists("./encoded/obfile.ps1"):
        os.replace("./encoded/obfile.ps1", f"obfile{tvalue}.ps1")

def encode_powershell(filepath,tvalue):
    os.system(f"python ./encode_powershell/encode_powershell_script.py -f {filepath} -o obfile{tvalue}.ps1")

def chimera(filepath):
    print('')

def Pyfuscator(filepath):
    print('')

def codecepticon(filepath):
    print('')

def characterfreq(filepath):
    print('')

#combine all powershell obfuscation tools and methods in a layered approaced for
#each powerscript to be obfuscated
def powershell_may_cry(toollist,scriptpath,tvalue):
    no_encode = 0
    no_launch = 0
    no_crypt = 0
    no_instealth = 0
    scriptname = os.path.basename(scriptpath)
    for x in toollist:
        print(f"method about to be called is:{x}")
        enc_call = False
        launch_call = False
        encrypt_call = False
        instealth_call = False
        if(len(x) == 4):
            if( re.search("[Ee]ncod", x[1]) or re.search("[Ee]ncod",x[3]) ):
                #print("Now in regex")
                no_encode += 1
                enc_call = True
            if( re.search("[Ll]aunch", x[1]) or re.search("[Ll]aunch", x[3]) ):
                no_launch += 1
                launch_call = True
            if( re.search("[Cc]rypt", x[1]) or re.search("[Cc]rypt", x[3]) ):
                no_crypt += 1
                encrypt_call = True
            if( re.search("[iI]nstealth", x[1])):
                no_instealth += 1
                instealth_call = True
        else:
            if(re.search("[eE]ncod", x[1])):
                no_encode += 1
                enc_call = True
            if(re.search("[Ll]aunch", x[1])):
                no_launch += 1
                launch_call = True
            if(re.search("[Cc]rypt", x[1])):
                no_crypt += 1
                encrypt_call = True
        if ((enc_call and no_encode > 1) or (launch_call and no_launch > 1) or (encrypt_call and no_launch > 1) or (instealth_call and no_instealth > 1)):
            continue
        else:
            if(toollist.index(x) == 0):
                if(len(x) == 4):
                    x[2](scriptpath,x[3],tvalue)
                else:
                    x[2](scriptpath,tvalue)
            else:
                while True:
                    if os.path.exists(f"obfile{tvalue}.ps1"):
                        time.sleep(0.5)
                        os.replace(f"obfile{tvalue}.ps1",f"inputfile{tvalue}.ps1")
                        if(len(x) == 4):
                            x[2](f"inputfile{tvalue}.ps1",x[3],tvalue)
                        else:
                            x[2](f"inputfile{tvalue}.ps1",tvalue)
                        break
                    else:
                        continue
            #time.sleep(6)
    endfilename = f"{scriptname}_{''.join(random.choice(letters) for i in range(10))}.ps1"
    if os.path.exists(f"obfile{tvalue}.ps1"):
        os.rename(f"obfile{tvalue}.ps1",endfilename)
        outputfile = open(endfilename, 'r')
        return outputfile

#Test commands
#instealth("./testscript.ps1","BetterXencrypt")
#inpowerob("./powerob/PowerUP.ps1")
#powfuscator("./testscript.ps1")
#obfuscatepy("PowerUp.ps1")
#goaround("./testscript.ps1")
#blanket("testscript.ps1")
#encode_powershell("testscript.ps1")

def report(methodlist,scriptname,tvalue):
    csvfile = open(f".\\powershell_may_cry_report{tvalue}.csv",'a')
    headers = ["inob-Token\\String\\1","inob-Token\\String\\2","inob-Token\\Command\\1","inob-Token\\Command\\2","inob-Token\\Command\\3","inob-Token\\Argument\\1","inob-Token\\Argument\\2","inob-Token\\Argument\\3","inob-Token\\Argument\\4","inob-Token\\Member\\1","inob-Token\\Member\\2","inob-Token\\Member\\3","inob-Token\\Member\\4","inob-Token\\Variable\\1","inob-Token\\Type\\1","inob-Token\\Type\\2","inob-Token\\Comment\\1","inob-Token\\Whitespace\\1","inob-Ast\\Namedattributeargumentast\\1","inob-Ast\\Paramblockast\\1","inob-Ast\\Scriptblockast\\1","inob-Ast\\Attributeast\\1","inob-Ast\\Binaryexpressionast\\1","inob-Ast\\Hashtableast\\1","inob-Ast\\Commandast\\1","inob-Ast\\Assignmentstatementast\\1","inob-Ast\\TypeExpressionast\\1","inob-Ast\\TypeConstraintast\\1","inob-String\\1","inob-String\\2","inob-String\\3","inob-Token\\All","inob-AST\\All","instealth-BetterXencrypt","instealth-PSObfuscation","instealth-ReverseB64","instealth-All","Chimera","Pyfuscator","Codecepticon","CharacterFreq","powerob","powfuscator","obfuscatepy","goaround","blanket","encpwsh","inob-Encoding\\1","inob-Encoding\\2","inob-Encoding\\3","inob-Encoding\\4","inob-Encoding\\5","inob-Encoding\\6","inob-Encoding\\7","inob-Encoding\\8","inob-Compress\\1","inob-Launcher\\PS\\0","inob-Launcher\\PS\\1","inob-Launcher\\PS\\2","inob-Launcher\\PS\\3","inob-Launcher\\PS\\4","inob-Launcher\\PS\\5","inob-Launcher\\PS\\6","inob-Launcher\\PS\\7","inob-Launcher\\PS\\8","inob-Launcher\\CMD\\0","inob-Launcher\\CMD\\1","inob-Launcher\\CMD\\2","inob-Launcher\\CMD\\3","inob-Launcher\\CMD\\4","inob-Launcher\\CMD\\5","inob-Launcher\\CMD\\6","inob-Launcher\\CMD\\7","inob-Launcher\\CMD\\8","inob-Launcher\\CMD\\9","inob-Launcher\\WMIC\\0","inob-Launcher\\WMIC\\1","inob-Launcher\\WMIC\\2","inob-Launcher\\WMIC\\3","inob-Launcher\\WMIC\\4","inob-Launcher\\WMIC\\5","inob-Launcher\\WMIC\\6","inob-Launcher\\WMIC\\7","inob-Launcher\\WMIC\\8","inob-Launcher\\Rundll\\0","inob-Launcher\\Rundll\\1","inob-Launcher\\Rundll\\2","inob-Launcher\\Rundll\\3","inob-Launcher\\Rundll\\4","inob-Launcher\\Rundll\\5","inob-Launcher\\Rundll\\6","inob-Launcher\\Rundll\\7","inob-Launcher\\Rundll\\8"]
    crow = [""] * len(headers)
    for method in methodlist:
        for header in headers:
            if(len(method) == 4):
                if(re.search(method[3].replace("\\","-"),header.replace("\\","-") )):
                    crow[headers.index(header)] = f"{crow[headers.index(header)]}x"
            else:
                if(re.search(method[1],header)):
                    crow[headers.index(header)] = f"{crow[headers.index(header)]}x"

        crowtxt = ','.join(crow)
    csvfile.write(f"\n{scriptname},{tvalue},{crowtxt}")
    csvfile.close()



obfmethods = [(1,"inob",inob,"Token\\String\\1"),(2,"inob",inob,"Token\\String\\1"),(3,"inob",inob,"Token\\String\\1"),
              (4,"inob",inob,"Token\\String\\2"),(5,"inob",inob,"Token\\String\\2"),(6,"inob",inob,"Token\\String\\2"),
              (7,"inob",inob,"Token\\Command\\1"),(8,"inob",inob,"Token\\Command\\1"),(9,"inob",inob,"Token\\Command\\1"),
              (10,"inob",inob,"Token\\Command\\2"),(11,"inob",inob,"Token\\Command\\2"),(12,"inob",inob,"Token\\Command\\2"),
              (13,"inob",inob,"Token\\Command\\3"),(14,"inob",inob,"Token\\Command\\3"),(15,"inob",inob,"Token\\Command\\3"),
              (16,"inob",inob,"Token\\Argument\\1"),(17,"inob",inob,"Token\\Argument\\1"),(18,"inob",inob,"Token\\Argument\\1"),
              (19,"inob",inob,"Token\\Argument\\2"),(20,"inob",inob,"Token\\Argument\\2"),(21,"inob",inob,"Token\\Argument\\2"),
              (22,"inob",inob,"Token\\Argument\\3"),(23,"inob",inob,"Token\\Argument\\3"),(24,"inob",inob,"Token\\Argument\\3"),
              (25,"inob",inob,"Token\\Argument\\4"),(26,"inob",inob,"Token\\Argument\\4"),(27,"inob",inob,"Token\\Argument\\4"),
              (28,"inob",inob,"Token\\Member\\1"),(29,"inob",inob,"Token\\Member\\1"),(30,"inob",inob,"Token\\Member\\1"),
              (31,"inob",inob,"Token\\Member\\2"),(32,"inob",inob,"Token\\Member\\2"),(33,"inob",inob,"Token\\Member\\2"),
              (34,"inob",inob,"Token\\Member\\3"),(35,"inob",inob,"Token\\Member\\3"),(36,"inob",inob,"Token\\Member\\3"),
              (37,"inob",inob,"Token\\Member\\4"),(38,"inob",inob,"Token\\Member\\4"),(39,"inob",inob,"Token\\Member\\4"),
              (40,"inob",inob,"Token\\Variable\\1"),(41,"inob",inob,"Token\\Variable\\1"),(42,"inob",inob,"Token\\Variable\\1"),
              (43,"inob",inob,"Token\\Type\\1"),(44,"inob",inob,"Token\\Type\\1"),(45,"inob",inob,"Token\\Type\\1"),
              (46,"inob",inob,"Token\\Type\\2"),(47,"inob",inob,"Token\\Type\\2"),(48,"inob",inob,"Token\\Type\\2"),
              (49,"inob",inob,"Token\\Comment\\1"),(50,"inob",inob,"Token\\Comment\\1"),(51,"inob",inob,"Token\\Comment\\1"),
              (52,"inob",inob,"Token\\Whitespace\\1"),(53,"inob",inob,"Token\\Whitespace\\1"),(54,"inob",inob,"Token\\Whitespace\\1"),
              (55,"inob",inob,"Ast\\Namedattributeargumentast\\1"),(56,"inob",inob,"Ast\\Namedattributeargumentast\\1"),(57,"inob",inob,"Ast\\Namedattributeargumentast\\1"),
              (58,"inob",inob,"Ast\\Paramblockast\\1"),(59,"inob",inob,"Ast\\Paramblockast\\1"),(60,"inob",inob,"Ast\\Paramblockast\\1"),
              (61,"inob",inob,"Ast\\Scriptblockast\\1"),(62,"inob",inob,"Ast\\Scriptblockast\\1"),(63,"inob",inob,"Ast\\Scriptblockast\\1"),
              (67,"inob",inob,"Ast\\Attributeast\\1"),(68,"inob",inob,"Ast\\Attributeast\\1"),(69,"inob",inob,"Ast\\Attributeast\\1"),
              (70,"inob",inob,"Ast\\Binaryexpressionast\\1"),(71,"inob",inob,"Ast\\Binaryexpressionast\\1"),(72,"inob",inob,"Ast\\Binaryexpressionast\\1"),
              (73,"inob",inob,"Ast\\Hashtableast\\1"),(74,"inob",inob,"Ast\\Hashtableast\\1"),(75,"inob",inob,"Ast\\Hashtableast\\1"),
              (76,"inob",inob,"Ast\\Commandast\\1"),(77,"inob",inob,"Ast\\Commandast\\1"),(78,"inob",inob,"Ast\\Commandast\\1"),
              (79,"inob",inob,"Ast\\Assignmentstatementast\\1"),(80,"inob",inob,"Ast\\Assignmentstatementast\\1"),(81,"inob",inob,"Ast\\Assignmentstatementast\\1"),
              (82,"inob",inob,"Ast\\TypeExpressionast\\1"),(83,"inob",inob,"Ast\\TypeExpressionast\\1"),(84,"inob",inob,"Ast\\TypeExpressionast\\1"),
              (85,"inob",inob,"Ast\\TypeConstraintast\\1"),(86,"inob",inob,"Ast\\TypeConstraintast\\1"),(87,"inob",inob,"Ast\\TypeConstraintast\\1"),
              (88,"inob",inob,"String\\1"),(89,"inob",inob,"String\\1"),(90,"inob",inob,"String\\1"),
              (91,"inob",inob,"String\\2"),(92,"inob",inob,"String\\2"),(93,"inob",inob,"String\\2"),
              (94,"inob",inob,"String\\3"),(95,"inob",inob,"String\\3"),(96,"inob",inob,"String\\3"),
              (161,"inob",inob,"Token\\All"),(161,"inob",inob,"Token\\All"),(161,"inob",inob,"Token\\All"),
              (162,"inob",inob,"AST\\All"),(162,"inob",inob,"AST\\All"),(162,"inob",inob,"AST\\All"),
              (97,"instealth",instealth,"BetterXencrypt"),#(98,"instealth",instealth,"BetterXencrypt"),(99,"instealth",instealth,"BetterXencrypt"),
              (100,"instealth",instealth,"PSObfuscation"),#(101,"instealth",instealth,"PSObfuscation"),(102,"instealth",instealth,"PSObfuscation"),
              (102,"instealth",instealth,"ReverseB64"),#(104,"instealth",instealth,"ReverseB64"),(105,"instealth",instealth,"ReverseB64"),
              (163,"instealth",instealth,"All"),
              (106,"powerob",powerob),(107,"powerob",powerob),(108,"powerob",powerob),
              (109,"powfuscator",powfuscator),(110,"powfuscator",powfuscator),(111,"powfuscator",powfuscator),
              (112,"obfuscatepy",obfuscatepy),(113,"obfuscatepy",obfuscatepy),(114,"obfuscatepy",obfuscatepy),
              (115,"goaround",goaround),(116,"goaround",goaround),(117,"goaround",goaround),
              (118,"blanket",blanket),(119,"blanket",blanket),(120,"blanket",blanket),
              #(121,"encpwsh",encode_powershell),(122,"encpwsh",encode_powershell),(123,"encpwsh",encode_powershell),
              #(97,"inob",inob,"Encoding\\1"),(98,"inob",inob,"Encoding\\1"),(99,"inob",inob,"Encoding\\1"),
              #(100,"inob",inob,"Encoding\\2"),(101,"inob",inob,"Encoding\\2"),(102,"inob",inob,"Encoding\\2"),
              #(103,"inob",inob,"Encoding\\3"),(104,"inob",inob,"Encoding\\3"),(105,"inob",inob,"Encoding\\3"),
              #(106,"inob",inob,"Encoding\\4"),(107,"inob",inob,"Encoding\\4"),(108,"inob",inob,"Encoding\\4"),
              #(109,"inob",inob,"Encoding\\5"),(110,"inob",inob,"Encoding\\5"),(111,"inob",inob,"Encoding\\5"),
              #(112,"inob",inob,"Encoding\\6"),(113,"inob",inob,"Encoding\\6"),(114,"inob",inob,"Encoding\\6"),
              #(115,"inob",inob,"Encoding\\7"),(116,"inob",inob,"Encoding\\7"),(117,"inob",inob,"Encoding\\7"),
              #(118,"inob",inob,"Encoding\\8"),(119,"inob",inob,"Encoding\\8"),(120,"inob",inob,"Encoding\\8"),
              (121,"inob",inob,"Compress\\1"),(122,"inob",inob,"Compress\\1"),(123,"inob",inob,"Compress\\1")
              #(124,"inob",inob,"Launcher\\PS\\0"),
              #(125,"inob",inob,"Launcher\\PS\\1"),
              #(126,"inob",inob,"Launcher\\PS\\2"),
              #(127,"inob",inob,"Launcher\\PS\\3"),
              #(128,"inob",inob,"Launcher\\PS\\4"),
              #(129,"inob",inob,"Launcher\\PS\\5"),
              #(130,"inob",inob,"Launcher\\PS\\6"),
              #(131,"inob",inob,"Launcher\\PS\\7"),
              #(132,"inob",inob,"Launcher\\PS\\8"),
              #(133,"inob",inob,"Launcher\\CMD\\0"),
              #(134,"inob",inob,"Launcher\\CMD\\1"),
              #(135,"inob",inob,"Launcher\\CMD\\2"),
              #(136,"inob",inob,"Launcher\\CMD\\3"),
              #(137,"inob",inob,"Launcher\\CMD\\4"),
              #(138,"inob",inob,"Launcher\\CMD\\5"),
              #(139,"inob",inob,"Launcher\\CMD\\6"),
              #(140,"inob",inob,"Launcher\\CMD\\7"),
              #(141,"inob",inob,"Launcher\\CMD\\8"),
              #(142,"inob",inob,"Launcher\\CMD\\9"),
              #(143,"inob",inob,"Launcher\\WMIC\\0"),
              #(144,"inob",inob,"Launcher\\WMIC\\1"),
              #(145,"inob",inob,"Launcher\\WMIC\\2"),
              #(146,"inob",inob,"Launcher\\WMIC\\3"),
              #(147,"inob",inob,"Launcher\\WMIC\\4"),
              #(148,"inob",inob,"Launcher\\WMIC\\5"),
              #(149,"inob",inob,"Launcher\\WMIC\\6"),
              #(150,"inob",inob,"Launcher\\WMIC\\7"),
              #(151,"inob",inob,"Launcher\\WMIC\\8"),
              #(152,"inob",inob,"Launcher\\Rundll\\0"),
              #(153,"inob",inob,"Launcher\\Rundll\\1"),
              #(154,"inob",inob,"Launcher\\Rundll\\2"),
              #(155,"inob",inob,"Launcher\\Rundll\\3"),
              #(156,"inob",inob,"Launcher\\Rundll\\4"),
              #(157,"inob",inob,"Launcher\\Rundll\\5"),
              #(158,"inob",inob,"Launcher\\Rundll\\6"),
              #(159,"inob",inob,"Launcher\\Rundll\\7"),
              #(160,"inob",inob,"Launcher\\Rundll\\8"),
             ]

obfmethods_mcombs = [(1,"inob",inob,"Token\\String\\1"),(2,"inob",inob,"Token\\String\\1"),(3,"inob",inob,"Token\\String\\1"),
              (4,"inob",inob,"Token\\String\\2"),(5,"inob",inob,"Token\\String\\2"),(6,"inob",inob,"Token\\String\\2"),
              (7,"inob",inob,"Token\\Command\\1"),(8,"inob",inob,"Token\\Command\\1"),(9,"inob",inob,"Token\\Command\\1"),
              (10,"inob",inob,"Token\\Command\\2"),(11,"inob",inob,"Token\\Command\\2"),(12,"inob",inob,"Token\\Command\\2"),
              (13,"inob",inob,"Token\\Command\\3"),(14,"inob",inob,"Token\\Command\\3"),(15,"inob",inob,"Token\\Command\\3"),
              (16,"inob",inob,"Token\\Argument\\1"),(17,"inob",inob,"Token\\Argument\\1"),(18,"inob",inob,"Token\\Argument\\1"),
              (19,"inob",inob,"Token\\Argument\\2"),(20,"inob",inob,"Token\\Argument\\2"),(21,"inob",inob,"Token\\Argument\\2"),
              (22,"inob",inob,"Token\\Argument\\3"),(23,"inob",inob,"Token\\Argument\\3"),(24,"inob",inob,"Token\\Argument\\3"),
              (25,"inob",inob,"Token\\Argument\\4"),(26,"inob",inob,"Token\\Argument\\4"),(27,"inob",inob,"Token\\Argument\\4"),
              (28,"inob",inob,"Token\\Member\\1"),(29,"inob",inob,"Token\\Member\\1"),(30,"inob",inob,"Token\\Member\\1"),
              (31,"inob",inob,"Token\\Member\\2"),(32,"inob",inob,"Token\\Member\\2"),(33,"inob",inob,"Token\\Member\\2"),
              (34,"inob",inob,"Token\\Member\\3"),(35,"inob",inob,"Token\\Member\\3"),(36,"inob",inob,"Token\\Member\\3"),
              (37,"inob",inob,"Token\\Member\\4"),(38,"inob",inob,"Token\\Member\\4"),(39,"inob",inob,"Token\\Member\\4"),
              (40,"inob",inob,"Token\\Variable\\1"),(41,"inob",inob,"Token\\Variable\\1"),(42,"inob",inob,"Token\\Variable\\1"),
              (43,"inob",inob,"Token\\Type\\1"),(44,"inob",inob,"Token\\Type\\1"),(45,"inob",inob,"Token\\Type\\1"),
              (46,"inob",inob,"Token\\Type\\2"),(47,"inob",inob,"Token\\Type\\2"),(48,"inob",inob,"Token\\Type\\2"),
              (49,"inob",inob,"Token\\Comment\\1"),(50,"inob",inob,"Token\\Comment\\1"),(51,"inob",inob,"Token\\Comment\\1"),
              (52,"inob",inob,"Token\\Whitespace\\1"),(53,"inob",inob,"Token\\Whitespace\\1"),(54,"inob",inob,"Token\\Whitespace\\1"),
              (55,"inob",inob,"Ast\\Namedattributeargumentast\\1"),(56,"inob",inob,"Ast\\Namedattributeargumentast\\1"),(57,"inob",inob,"Ast\\Namedattributeargumentast\\1"),
              (58,"inob",inob,"Ast\\Paramblockast\\1"),(59,"inob",inob,"Ast\\Paramblockast\\1"),(60,"inob",inob,"Ast\\Paramblockast\\1"),
              (61,"inob",inob,"Ast\\Scriptblockast\\1"),(62,"inob",inob,"Ast\\Scriptblockast\\1"),(63,"inob",inob,"Ast\\Scriptblockast\\1"),
              (67,"inob",inob,"Ast\\Attributeast\\1"),(68,"inob",inob,"Ast\\Attributeast\\1"),(69,"inob",inob,"Ast\\Attributeast\\1"),
              (70,"inob",inob,"Ast\\Binaryexpressionast\\1"),(71,"inob",inob,"Ast\\Binaryexpressionast\\1"),(72,"inob",inob,"Ast\\Binaryexpressionast\\1"),
              (73,"inob",inob,"Ast\\Hashtableast\\1"),(74,"inob",inob,"Ast\\Hashtableast\\1"),(75,"inob",inob,"Ast\\Hashtableast\\1"),
              (76,"inob",inob,"Ast\\Commandast\\1"),(77,"inob",inob,"Ast\\Commandast\\1"),(78,"inob",inob,"Ast\\Commandast\\1"),
              (79,"inob",inob,"Ast\\Assignmentstatementast\\1"),(80,"inob",inob,"Ast\\Assignmentstatementast\\1"),(81,"inob",inob,"Ast\\Assignmentstatementast\\1"),
              (82,"inob",inob,"Ast\\TypeExpressionast\\1"),(83,"inob",inob,"Ast\\TypeExpressionast\\1"),(84,"inob",inob,"Ast\\TypeExpressionast\\1"),
              (85,"inob",inob,"Ast\\TypeConstraintast\\1"),(86,"inob",inob,"Ast\\TypeConstraintast\\1"),(87,"inob",inob,"Ast\\TypeConstraintast\\1"),
              (88,"inob",inob,"String\\1"),(89,"inob",inob,"String\\1"),(90,"inob",inob,"String\\1"),
              (91,"inob",inob,"String\\2"),(92,"inob",inob,"String\\2"),(93,"inob",inob,"String\\2"),
              (94,"inob",inob,"String\\3"),(95,"inob",inob,"String\\3"),(96,"inob",inob,"String\\3"),
              (161,"inob",inob,"Token\\All"),(161,"inob",inob,"Token\\All"),(161,"inob",inob,"Token\\All"),
              (162,"inob",inob,"AST\\All"),(162,"inob",inob,"AST\\All"),(162,"inob",inob,"AST\\All"),
              (97,"inob",inob,"Encoding\\1"),(98,"inob",inob,"Encoding\\1"),(99,"inob",inob,"Encoding\\1"),
              (100,"inob",inob,"Encoding\\2"),(101,"inob",inob,"Encoding\\2"),(102,"inob",inob,"Encoding\\2"),
              (103,"inob",inob,"Encoding\\3"),(104,"inob",inob,"Encoding\\3"),(105,"inob",inob,"Encoding\\3"),
              (106,"inob",inob,"Encoding\\4"),(107,"inob",inob,"Encoding\\4"),(108,"inob",inob,"Encoding\\4"),
              (109,"inob",inob,"Encoding\\5"),(110,"inob",inob,"Encoding\\5"),(111,"inob",inob,"Encoding\\5"),
              (112,"inob",inob,"Encoding\\6"),(113,"inob",inob,"Encoding\\6"),(114,"inob",inob,"Encoding\\6"),
              (115,"inob",inob,"Encoding\\7"),(116,"inob",inob,"Encoding\\7"),(117,"inob",inob,"Encoding\\7"),
              (118,"inob",inob,"Encoding\\8"),(119,"inob",inob,"Encoding\\8"),(120,"inob",inob,"Encoding\\8"),
              (121,"inob",inob,"Compress\\1"),(122,"inob",inob,"Compress\\1"),(123,"inob",inob,"Compress\\1"),
              (124,"inob",inob,"Launcher\\PS\\0"),
              (125,"inob",inob,"Launcher\\PS\\1"),
              (126,"inob",inob,"Launcher\\PS\\2"),
              (127,"inob",inob,"Launcher\\PS\\3"),
              (128,"inob",inob,"Launcher\\PS\\4"),
              (129,"inob",inob,"Launcher\\PS\\5"),
              (130,"inob",inob,"Launcher\\PS\\6"),
              (131,"inob",inob,"Launcher\\PS\\7"),
              (132,"inob",inob,"Launcher\\PS\\8"),
              (133,"inob",inob,"Launcher\\CMD\\0"),
              (134,"inob",inob,"Launcher\\CMD\\1"),
              (135,"inob",inob,"Launcher\\CMD\\2"),
              (136,"inob",inob,"Launcher\\CMD\\3"),
              (137,"inob",inob,"Launcher\\CMD\\4"),
              (138,"inob",inob,"Launcher\\CMD\\5"),
              (139,"inob",inob,"Launcher\\CMD\\6"),
              (140,"inob",inob,"Launcher\\CMD\\7"),
              (141,"inob",inob,"Launcher\\CMD\\8"),
              (142,"inob",inob,"Launcher\\CMD\\9"),
              (143,"inob",inob,"Launcher\\WMIC\\0"),
              (144,"inob",inob,"Launcher\\WMIC\\1"),
              (145,"inob",inob,"Launcher\\WMIC\\2"),
              (146,"inob",inob,"Launcher\\WMIC\\3"),
              (147,"inob",inob,"Launcher\\WMIC\\4"),
              (148,"inob",inob,"Launcher\\WMIC\\5"),
              (149,"inob",inob,"Launcher\\WMIC\\6"),
              (150,"inob",inob,"Launcher\\WMIC\\7"),
              (151,"inob",inob,"Launcher\\WMIC\\8"),
              (152,"inob",inob,"Launcher\\Rundll\\0"),
              (153,"inob",inob,"Launcher\\Rundll\\1"),
              (154,"inob",inob,"Launcher\\Rundll\\2"),
              (155,"inob",inob,"Launcher\\Rundll\\3"),
              (156,"inob",inob,"Launcher\\Rundll\\4"),
              (157,"inob",inob,"Launcher\\Rundll\\5"),
              (158,"inob",inob,"Launcher\\Rundll\\6"),
              (159,"inob",inob,"Launcher\\Rundll\\7"),
              (160,"inob",inob,"Launcher\\Rundll\\8"),
             ]

def exec_pmy(pcombs,tvalue,methods,i_dir, o_dir):
    try:
        scripts_dir = os.listdir(i_dir)
        no_combinations = pcombs
        combs = combinations_plus(methods, no_combinations)
        random.shuffle(combs)
        os.mkdir(os.path.join(o_dir,f"Combination_{no_combinations}",))
        for n in combs:
            for x in scripts_dir:
                ffile = powershell_may_cry(n,f"{i_dir}\\{x}",tvalue)
                if(ffile):
                    ffile_name = ffile.name
                    ffile.close()
                    report(n,ffile_name,tvalue)
                    os.rename(ffile_name,f"{o_dir}/Combination_{no_combinations}/{ffile_name}")
                    if os.path.exists(f"obfile{tvalue}.ps1"):
                        os.remove(f"obfile{tvalue}.ps1")
                    if os.path.exists(f"inputfile{tvalue}.ps1"):
                        os.remove(f"inputfile{tvalue}.ps1")
    except Exception as e:
        print(f"Exception in thread {tvalue}: {e}")
        import traceback
        traceback.print_exc()



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multithreaded PowerShell obfuscation engine")
    parser.add_argument("-i", "--input-dir", required=False, help="Directory containing PowerShell scripts to obfuscate")
    parser.add_argument("-o", "--output-dir", required=False, help="Directory to write output scripts to")
    parser.add_argument("-t", "--threads", type=int, required=False, help="Number of threads to use")
    parser.add_argument("-c", "--combinations", type=str, required=False, help="Number of combinations to run concurrently for generating obfuscated scripts\nseparated by comma e.g 1,2,3..")

    args = parser.parse_args()

    if not args.input_dir or not args.output_dir or not args.threads:
        parser.print_help()
        exit(1)
    
    clist = [int(x) for x in args.combinations.split(',')]
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=args.threads);
    for c in clist:
        executor.submit(exec_pmy, c, c, obfmethods_mcombs, args.input_dir, args.output_dir)
    
    executor.shutdown(wait=True)

