# -*- coding: utf-8 -*-
import sys, os, re

sys.path.append(os.path.abspath('..'))
import staticdhcpdlib as module
sys.path.remove(os.path.abspath('..'))
sys.path.append(os.path.abspath('../staticdhcpdlib'))

extensions = ['sphinx.ext.autodoc', 'sphinx.ext.todo', 'sphinx.ext.coverage', 'sphinx.ext.viewcode']
templates_path = ['_templates']
source_suffix = '.rst'
master_doc = 'index'

project = u'staticDHCPd'
copyright = module.COPYRIGHT
version = re.match('^(\d+\.\d+)', module.VERSION).group(1)
release = module.VERSION

exclude_trees = ['_build']

pygments_style = 'sphinx'

html_theme = 'default'
html_static_path = ['_static']
html_show_sourcelink = False

htmlhelp_basename = 'staticDHCPddoc'

latex_documents = [
  ('index', 'staticDHCPd.tex', u'staticDHCPd documentation',
   re.search(', (.*?) <', module.COPYRIGHT).group(1), 'manual'),
]
