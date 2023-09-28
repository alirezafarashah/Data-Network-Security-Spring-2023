from math import gcd
from functools import reduce
from collections import Counter
import matplotlib.pyplot as plt
alphabet = {"ا": 0, "ب": 1, "پ": 2, "ت": 3, "ث": 4, "ج": 5, "چ": 6, "ح": 7, "خ": 8, "د": 9, "ذ": 10, "ر": 11, "ز": 12,
            "ژ": 13, "س": 14, "ش": 15,
            "ص": 16, "ض": 17, "ط": 18, "ظ": 19, "ع": 20, "غ": 21, "ف": 22, "ق": 23, "ک": 24, "گ": 25, "ل": 26, "م": 27,
            "ن": 28,
            "و": 29,
            "ه": 30, "ی": 31}


def find_gcd(list):
    x = reduce(gcd, list)
    return x


def repeated_tokens(words):
    factors = []
    for i in range(len(words)):
        c = 0
        for j in range(i + 1, len(words)):
            c += len(words[j])
            if words[i] == words[j]:
                factors.append(c)
    return factors


def find_key_length(ctext):
    factors = repeated_tokens(ctext)
    print(factors)
    return find_gcd(factors)


def get_freq(ctext, key_len):
    res = []
    for i in range(key_len):
        res.append(Counter(ctext[i:-1:key_len]))
    return res


def decode(ctext, key):
    global alphabet
    plain_text = ""
    idx = 0
    for word in ctext.split(" "):
        for i in range(len(word)):
            plain_text += list(alphabet.keys())[
                list(alphabet.values()).index((alphabet[word[i]] - alphabet[key[idx]]) % 32)]
            idx += 1
            idx = idx % 4
        plain_text += " "
    return plain_text


ctext = "تپکغج طغعث ژرا عر فرز رکاچق شددچ کوچف ل اچقم هدف ل ظعضم فع قهغج فوضطذ هضچذر ثذرگسدد مصح رگمح فو ژح " \
        "حلثزذ ها ثح هوچرگ غجثوظ عخدظدس خغ ذثزغ چ وضغث ظال کزوضپرم ققف ما شد گطکسم فچع جطدحچ هخفلزز لچ ط " \
        "میوص جسلغجگا وچفچ اچق چطث حنب شحنض کع ل ققف معش وضغث حجطعع خطغ گلص ذرد ظعضم سیسم فچع " \
        "گطکس ل کد حلثزد خغ ذف جطدحچ غیسوف عخد محرخص مجلد بفچ ط دخ معش وضغث حجطعع خطغ ضمغعچ معش " \
        "حفرز له قطف وب دخ جطدگا ژح توذظدو فخرالط خ گطکسمظد زجطدحچ ققف فرز رکاچق معش حفرزدوص زر هاضخوضث " \
        "جعصدح فرز ژر فخر ل غغ رنض جرگ ژح زخ تیفم غقس هوچف ل فطرگ ژح فلب اذوصز رگغج تم ژث ثظکحرگه شحوض " \
        "صرق وچلن هدفگه بد وژجخگ کچ عواخ"

max_key_length = find_key_length(ctext.split(" "))

print(max_key_length)

freqs = get_freq(ctext.replace(' ', ''), max_key_length)
print(freqs[0])
plt.bar(freqs[0].keys(), freqs[0].values(), 1, color='g')
print(freqs[1])
print(freqs[2])
print(freqs[3])

key = "دروغ"
print(decode(ctext, key))
