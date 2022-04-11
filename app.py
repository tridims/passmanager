#!/usr/bin/env python3

import typer
from PasswordManager import PasswordManager

app = typer.Typer()
password_manager = PasswordManager()


@app.command()
def init():
    if password_manager.init_app():
        typer.echo('Password manager initialized in home directory')
    else:
        typer.echo('Password manager already initialized')


@app.command()
def add(site: str, username: str, pw: str):
    main_password = typer.prompt('Enter your password: ', hide_input=True)
    r = password_manager.add_password(site, username, pw, main_password)
    if not r:
        typer.echo("Error: Password not added")
    else:
        typer.echo("Password added")


@app.command()
def list_pass():
    list_saved_pw = password_manager.get_list_password_file_path()
    if len(list_saved_pw) == 0:
        typer.echo("No password saved")
    else:
        typer.echo("List of saved passwords:")
        for pw in list_saved_pw:
            typer.echo(f' {pw}')


@app.command()
def get(site: str, username: str):
    main_password = typer.prompt('Enter your password: ', hide_input=True)
    r = password_manager.get_password(site, username, main_password)
    if not r:
        typer.echo("Error: Password not found")
    else:
        typer.echo(f'pass : {r}')


if __name__ == "__main__":
    app()
