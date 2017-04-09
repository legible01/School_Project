TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
    packet_info.cpp \
    send_arp.cpp
LIBS += -lpcap

HEADERS += \
    packet_info.h

