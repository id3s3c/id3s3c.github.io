# id3s3c.github.io

## Development setup

Install ruby

```bash
sudo apt-get install ruby-full build-essential zlib1g-dev -y`
echo '# Install Ruby Gems to ~/gems' >> ~/.bashrc
echo 'export GEM_HOME="$HOME/gems"' >> ~/.bashrc
echo 'export PATH="$HOME/gems/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Install jekyll
gem install jekyll bundler
```

## Update

```bash
bundle update

# Start local server
bundle exec jekyll serve
```
