" Reference: https://davidspencer.xyz/posts/neovim-as-an-ide-python/
" Reference: https://jdhao.github.io/2018/12/24/centos_nvim_install_use_guide_en/#file-managing-and-exploration-plugin

syntax on                       "syntax highlighting, see :help syntax
filetype plugin indent on       "file type detection, see :help filetype
set mouse=r			            "set mouse mode to r
set number			            "display line number
set backspace=indent,eol,start  "ensure proper backspace functionality
set undodir=~/.cache/nvim/undo  "undo ability will persist after exiting file
set undofile                    "see :help undodir and :help undofile
set incsearch                   "see results while search is being typed, see :help incsearch
set smartindent                 "auto indent on new lines, see :help smartindent
set ic                          "ignore case when searching
set expandtab                   "expanding tab to spaces
set tabstop=4                   "setting tab to 4 columns
set shiftwidth=4                "setting tab to 4 columns
set softtabstop=4               "setting tab to 4 columns
set showmatch                   "display matching bracket or parenthesis
set hlsearch incsearch          "highlight all pervious search pattern with incsearch
"set clipboard=unnamedplus       "yank also to clipboard
highlight ColorColumn ctermbg=9 "display ugly bright red bar at color column number
setlocal spell spelllang=en_us  "enable spell checking - default to en_us


"---------------PLUGINS------------------------
" --> VimPlug Plugins
" VIM PLUG INSTALLATION:  curl -fLo "${XDG_DATA_HOME:-$HOME/.local/share}"/nvim/site/autoload/plug.vim  --create-dirs https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim
"vim-plug configuration, plugins will be installed in ~/.config/nvim/plugged
call plug#begin() 

" nvim auto completion
Plug 'Shougo/deoplete.nvim', { 'do': ':UpdateRemotePlugins' }
let g:deoplete#enable_at_startup = 1

" Code syntax check and build automation
" For python install linter: pip install pylint
Plug 'neomake/neomake'

" Deoplete Python Jedi autocompletion and static analysis lib 
" Needs pynvim and jedi to be installed: pip install pynvim jedi
Plug 'deoplete-plugins/deoplete-jedi'

" C deoplete autocompletion plugin using vim-plug
Plug 'deoplete-plugins/deoplete-clang'

" Go language support for Vim
Plug 'fatih/vim-go', { 'do': ':GoUpdateBinaries' }
let g:go_doc_popup_window = 1 " Open go doc in popup window

"Lighline
Plug 'itchyny/lightline.vim'

" Automatic quote and bracket completion
Plug 'jiangmiao/auto-pairs'

" Comments Plugin
Plug 'scrooloose/nerdcommenter'

" Code Autoformat Plugin
" Each language need its formatter to be installed; python ex: pip install
" yapf
Plug 'sbdchd/neoformat'

" File managing and exploration
" !!! for live_grep install ripgrep (https://github.com/BurntSushi/ripgrep)
Plug 'nvim-tree/nvim-web-devicons'
Plug 'scrooloose/nerdtree'
Plug 'nvim-lua/plenary.nvim'
Plug 'nvim-telescope/telescope.nvim', { 'tag': '0.1.1' }

" nightfly theme plugin
Plug 'bluz71/vim-nightfly-guicolors', { 'branch': 'legacy' }
let g:lightline = { 'colorscheme': 'nightfly' }
let g:nightflyCursorColor = v:true

" Markdown preview
Plug 'iamcco/markdown-preview.nvim', { 'do': 'cd app && yarn install' }
let g:mkdp_browser = '/usr/bin/chromium'
call plug#end()



"----------------------------------------------

"-----------------THEME------------------------

" Needed to make GUI themes work
set termguicolors

" Activate Theme, check termguicolors option for true colors terminals
colorscheme nightfly

" Needed to make tmux work properly with theme
let &t_8f = "\<Esc>[38;2;%lu;%lu;%lum"
let &t_8b = "\<Esc>[48;2;%lu;%lu;%lum"

"----------------------------------------------

"-----------------COMMON-----------------------

" --> Autocomplete configuration
autocmd InsertLeave,CompleteDone * if pumvisible() == 0 | pclose | endif " autoclose preview window

" Tab completion
inoremap <expr><tab> pumvisible() ? "\<c-n>" : "\<tab>"

" Enable linters
"let g:neomake_python_enabled_makers = ['pylint']

" Full config: when writing or reading a buffer, and on changes in insert and
" normal mode (after 500ms; no delay when writing).
"call neomake#configure#automake('nrwi', 500)

" NERDTree Keybindings
nnoremap <silent> l :NERDTreeToggle<CR>
nnoremap <silent> L :NERDTreeFocus<CR> 

" Telescope Keybindings
nnoremap <silent>ff :Telescope find_files<CR>
nnoremap <silent>fg :Telescope live_grep<CR>
nnoremap <silent>fb :Telescope buffers <CR>
nnoremap <silent>fh :Telescope help_tags<CR>

" MarkdownPreviewToggle
nmap <C-a>p :MarkdownPreviewToggle<CR>
"----------------------------------------------

" Enable or disable clipboard type
nnoremap <C-a>a :set clipboard=unnamedplus<CR>
nnoremap <C-a>z :set clipboard=unnamed<CR>


"-----------------LANGUAGE SPECIFIC------------

" --> Bash Script
"  When bash filetype is detected, F5 can be used to execute Script
autocmd FileType sh nnoremap <buffer> <F5> :w<cr>:exec '!clear'<cr>:exec '!/bin/bash' shellescape(expand('%:p'), 1)<cr>
autocmd FileType sh nnoremap <buffer> <F4> :w<cr>:exec '!clear'<cr>:exec 'set splitright'<cr>:exec 'vsplit term://shellcheck' shellescape(expand('%:p'), 1)<cr><cr>

" --> C Script
"  When c filetype is detected, F5 can be used to execute Script
autocmd FileType c nnoremap <buffer> <F5> :w<cr>:exec '!clear'<cr>:exec '!gcc -o' shellescape(expand('%:p')[:-3], 1) shellescape(expand('%:p'), 1) <cr>:exec '!'shellescape(expand('%:p')[:-3], 1)<cr>

" --> Golang 
"  When go filetype is detected, F5 can be used to execute Script
autocmd FileType go nnoremap <buffer> <F5> :w<cr>:exec '!clear'<cr>:exec 'GoRun'<cr>

" Deoplete Go autocompletion with gopls and vim-go
" Needs gopls to be installed: go install golang.org/x/tools/gopls@latest
call deoplete#custom#option('omni_patterns', {
\ 'go': '[^. *\t]\.\w*',
\})

" --> Python
" When python filetype is detected, F5 can be used to execute script 
autocmd FileType python nnoremap <buffer> <F5> :w<cr>:exec '!clear'<cr>:exec '!python3' shellescape(expand('%:p'), 1)<cr>

" display color when line reaches pep8 standards
" autocmd FileType python 	set colorcolumn=80              


"---------------------------------------------
