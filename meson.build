project('smolhttpd', 'cpp',
  version : '0.1',
  default_options : ['warning_level=3', 'cpp_std=c++14'])
link_args = ['-lssl', '-lcrypto']
executable('smolhttpd',
           'src/smolhttpd.cpp',
           install : true, link_args: link_args)
