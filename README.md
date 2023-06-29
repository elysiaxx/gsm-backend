gsm-backend service
-------------------

gsm-backend service Deployment Documentation
-----------------------------------

# 1. Project Structure
This project consists of the following components:

- __app__
- __settings__
- __README.md__
- __manage.py__
- __requirements.txt__
- __.gitignore__

# 2. Deployment
## 2.1. Minimum Requirements (main libraries)
```yaml
- flask
- flask-restx
```


## 2.2. Deployment

- Install miniconda, download [here](https://docs.conda.io/en/latest/miniconda.html).

E.g, For Linux distribution:
```bash
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
```
- Create conda environment and activate it:
```bash
conda create --name <env_name>
conda activate <env_name>
```
- Install required dependencies:

```bash
sudo apt install unixodbc-dev
pip install -r requirements.txt
```
- Run project:
```bash
python manage.py
```

**Notes**: To run project in the background, you should use [**`tmux`**](https://gist.github.com/ladin157/d2f6bfa09df584ec13f3f6e2055952b7) to manage processes. 

# 3. Tips
- Install all dependencies in Linux distribution before installing the packages to avoiding errors during installation.
- If you get any trouble while installing a dependency, install it separately using conda.
```bash
conda install <package_name>
``` 
- Each service is running under `tmux` process or as a background service.
