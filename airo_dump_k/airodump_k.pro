TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
    main.cpp \
    radiotap.cpp \
    mac80211.cpp \
    printdata.cpp

HEADERS += \
    radiotap.h \
    mac80211.h \
    printdata.h
LIBS += -lpcap


