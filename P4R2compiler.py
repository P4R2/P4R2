import jinja2
import json
import argparse

# Path information.
TEMPLATE_PATH = 'templates/'
P4_PATH = 'p4src/'
CONFIG_PATH = './'

if __name__ == "__main__":

    # Extract configs
    with open(CONFIG_PATH + 'config.json', 'r') as fr:
        CONF = json.load(fr)

    CONF["parsing_len"] = len(CONF["parsing_logic"])

    env = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_PATH),  trim_blocks=True, lstrip_blocks=True)  
    # Generate p4r2.p4 and metadata.p4
    template0 = env.get_template('p4r2.p4template')
    template_out = template0.render(CONF=CONF)
    with open(P4_PATH + 'p4r2.p4', 'w') as fw:
        fw.writelines(template_out)
        fw.close()

    template1 = env.get_template('metadata.p4template')
    template_out = template1.render(CONF=CONF)
    with open(P4_PATH + 'metadata.p4', 'w') as fw:
        fw.writelines(template_out)
        fw.close()


