import logging

def get_logger(filename:str):
        logformat = "%(asctime)s - %(message)s"
        logging.basicConfig(filename=filename,filemode='a',format=logformat,datefmt='%a %d %b %Y %H:%M:%S',level=logging.INFO)
        return logging.getLogger()