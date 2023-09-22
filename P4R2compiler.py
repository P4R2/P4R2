import jinja2
import json
import argparse

# Path infomation.
TEMPLATE_PATH = 'templates/'
P4_PATH = 'p4src/'


def check_args(l):
    for i in range(len(l)):
        try:
            l[i]= int(l[i])
        except:
            print("Wrong arguments")
            exit(1)
    return l


parser = argparse.ArgumentParser()
parser.add_argument("--mod_info", type=str, dest='i', required=True, help="number of five modules, ex: \'1,1,2,4,2\'")
parser.add_argument("--actions", type=str, dest='a', required=True, help="the action you need to use in ActionReconfiguration module, see \'./readme.md\' for more help")

args = parser.parse_args()

moduleinfo = check_args(args.i.split(','))
actions = check_args(args.a.split(','))

# generation configs
CONF = [moduleinfo, actions]


if __name__ == "__main__":
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_PATH),  trim_blocks=True, lstrip_blocks=True)  
    # Generating rr.p4
    template = env.get_template('rr.p4template')
    template_out = template.render(CONF=CONF)
    with open(P4_PATH + 'rr.p4', 'w') as f:
        f.writelines(template_out)
        f.close()


