#!/usr/bin/env python
# -*- coding: utf-8 -*-
#autor samir sanchez garnica @sasaga92


def script_colors(color_type, text):
    color_end = '\033[0m'

    if color_type.lower() == "r" or color_type.lower() == "red":
        red = '\033[91m'
        text = red + text + color_end
    elif color_type.lower() == "lgray":
        gray = '\033[2m'
        text = gray + text + color_end
    elif color_type.lower() == "gray":
        gray = '\033[90m'
        text = gray + text + color_end
    elif color_type.lower() == "strike":
        strike = '\033[9m'
        text = strike + text + color_end
    elif color_type.lower() == "underline":
        underline = '\033[4m'
        text = underline + text + color_end
    elif color_type.lower() == "b" or color_type.lower() == "blue":
        blue = '\033[94m'
        text = blue + text + color_end
    elif color_type.lower() == "g" or color_type.lower() == "green":
        green = '\033[92m'
        text = green + text + color_end
    elif color_type.lower() == "y" or color_type.lower() == "yellow":
        yellow = '\033[93m'
        text = yellow + text + color_end
    elif color_type.lower() == "c" or color_type.lower() == "cyan":
        cyan = '\033[96m'
        text = cyan + text + color_end
    elif color_type.lower() == "cf" or color_type.lower() == "cafe":
        cafe = '\033[52m'
        text = cafe + text + color_end
    elif color_type.lower() == "bk" or color_type.lower() == "black":
        black ='\033[30m' 
        text = black + text + color_end
    elif color_type.lower() == "light_purple" or color_type.lower() == "lpurple":
        lpurple = '\033[94m'
        text = lpurple + text + color_end
    elif color_type.lower() == "pple" or color_type.lower() == "purple":
        purple = '\033[95m'
        text = purple + text + color_end
    else:
        return text
    return  text


