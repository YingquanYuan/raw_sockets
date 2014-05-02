#!/usr/bin/env python
import argparse
import os

from logger import init_logger, get_logger
from utils import Timer
from rawurllib import urlretrieve


def parse_arguments():
    '''
    Set up the arg parser and parse the command line
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument('url', type=str,
                        help='The url the raw sockets will fetch')
    parser.add_argument('-p', '--port', type=int,
                        default=80,
                        help='The port number of the target http server')
    parser.add_argument('-i', '--interface', type=str,
                        default='eth0',
                        help='The interface used to look up local IP address')
    parser.add_argument('-d', '--directory', type=str, action='store',
                        default='.',
                        help='The target directory to store the'
                        + ' downloaded file')
    parser.add_argument('-v', '--verbosity', action='count',
                        default=0,
                        help='Incresing program verbosity')
    parser.add_argument('-l', '--logfile', type=str, action='store',
                        help='The name of the log file. If specified,'
                        + ' program output will be logged into the file'
                        + ' instead of outputed to stdout')
    return parser.parse_args()


def main():
    # parse command line arguments
    args = parse_arguments()

    # init logging
    init_logger(args.logfile, args.verbosity)
    logger = get_logger(os.path.basename(__file__))
    logger.info('Running the rawhttpget script in verbosity level: %d'
                % args.verbosity)

    # download the file with the given url
    logger.info('Downloading file at: %s' % args.url)
    with Timer() as t:
        try:
            filepath = urlretrieve(args.url, args.port, args.directory)
        except (ValueError, RuntimeError) as e:
            logger.error('%s, quit' % e.message)
            exit(1)
    logger.info('File is downloaded to: %s' % filepath)
    logger.info('Time taken: %ss' % t.duration)


if __name__ == '__main__':
    main()
