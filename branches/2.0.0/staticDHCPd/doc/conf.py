# -*- coding: utf-8 -*-
import sys, os, re

sys.path.append(os.path.abspath('../staticdhcpdlib'))
sys.path.append(os.path.abspath('..'))
import staticdhcpdlib as module

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.todo',
    'sphinx.ext.coverage',
    'sphinx.ext.viewcode',
]
templates_path = ['_templates']
source_suffix = '.rst'
master_doc = 'index'

project = u'staticDHCPd'
copyright = module.COPYRIGHT
version = re.match('^(\d+\.\d+)', module.VERSION).group(1)
release = module.VERSION

exclude_trees = ['_build']

pygments_style = 'sphinx'

autodoc_member_order = 'bysource'
autoclass_content = 'init'

html_theme = 'default'
html_static_path = ['_static']
html_show_sourcelink = False

htmlhelp_basename = 'staticDHCPddoc'

latex_documents = [
  ('index', 'staticDHCPd.tex', u'staticDHCPd documentation',
   re.search(', (.*?) <', module.COPYRIGHT).group(1), 'manual'),
]
