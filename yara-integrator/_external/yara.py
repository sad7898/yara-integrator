import yara

def main():
    rule = yara.compile(source='rule foo: bar {strings: $a = "lmn" condition: $a}')
    matches = rule.match(data='abcdefgjiklmnoprstuvwxyz')


if __name__ =="__main__":
    main()