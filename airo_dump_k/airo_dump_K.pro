TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
    main.cpp \
    radiotap.cpp \
    mac80211.cpp

HEADERS += \
    radiotap.h \
    mac80211.h
LIBS += -lpcap
