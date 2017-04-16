TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.cpp \
    packet_info.cpp \
    generate_packet.cpp
LIBS += -lpcap

HEADERS += \
    packet_info.h \
    generate_packet.h
