from scapy.all import *

FILTER_POS = 0
PRINT_POS = 1

DNS_RESPONSE = 1

WEATHER_IP = "34.218.16.79"
WEATHER_ANSWER = b"200:ANSWER"

GET_MSG = b"GET"
HTTP_SEP = ' '
GET_DIR_POS = 1


def filter_dns(packet) :
    """Returns if a given packet is a packet dns
    :param packet: A given packet
    :return: If the packet is a packet dns
    """
    return DNS in packet and packet[DNS].qr == DNS_RESPONSE and packet[DNS.an != None]


def filter_weather(packet) :
    """Returns if a given packet is a server packet
    :param packet: A given packet
    :return: If the packet is a server packet
    """
    return IP in packet and packet[IP].src == WEATHER_IP and Raw in packet and WEATHER_ANSWER in packet[Raw].load


def filter_get(packet) :
    """Returns if a given packet is a http GET
    :param packet: A given packet
    :return: If the packet is a http get
    """
    return Raw in packet and GET_MSG in packet[Raw].load


def print_dns(packet) :
    """

    :param packet: A given packet
    """
    print(f"{packet[DNS].an.rrname}: {packet[DNS].an.rdata}")


def print_weather(packet) :
    """

    :param packet: A given packet
    """
    print(packet[Raw].load.decode())


def print_get(packet) :
    """

    :param packet: A given packet
    """
    print(packet[Raw].load.decode().split(HTTP_SEP)[GET_DIR_POS])


OPTIONS = {"1" : (filter_dns, print_dns),
           "2" : (filter_weather, print_weather),
           "3" : (filter_get, print_get)}


def main() :
    while True :
        option = input("1 - sniff dns\n2 - sniff weather\n3 - sniff get\nEnter your option: ")

        try :
            sniff(lfilter=OPTION[option][FILTER_POS], prn=OPTION[option][PRINT_POS])
        except Exception as e :
            print("Error: ", e)


if __name__ == "__main__" :
    main()