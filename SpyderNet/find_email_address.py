import requests
import re
from bs4 import BeautifulSoup
import urllib.robotparser
import socket
import argparse
import sys
import time
from urllib.parse import urljoin, urlparse
import ssl  # Import the ssl module


def get_robots_txt(url):
    """
    Retrieves the robots.txt file from a website.

    Args:
        url (str): The base URL of the website.

    Returns:
        str: The content of the robots.txt file, or None if it cannot be retrieved.
    """
    robots_url = urllib.parse.urljoin(url, "robots.txt")
    try:
        response = requests.get(robots_url, timeout=10, verify=False)  # Add verify=False here
        if response.status_code == 200:
            return response.text
        elif response.status_code == 404:
            return None  # robots.txt not found is not an error
        else:
            print(f"[-] Error retrieving robots.txt: {response.status_code}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"[-] Error retrieving robots.txt: {e}")
        return None



def can_crawl(url, user_agent="MyEmailScraper"):
    """
    Checks if the user agent is allowed to crawl the given URL based on robots.txt.

    Args:
        url (str): The URL to check.
        user_agent (str, optional): The user agent string to use. Defaults to "MyEmailScraper".

    Returns:
        bool: True if crawling is allowed, False otherwise.
    """
    try:
        parsed_url = urllib.parse.urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"  # Ensure no trailing slash
        rp = urllib.robotparser.RobotFileParser()
        robots_content = get_robots_txt(base_url)

        if robots_content:
            rp.parse(robots_content)
            return rp.can_fetch(user_agent, url)
        else:
            return True  # If there is no robots.txt, we assume we can crawl
    except Exception as e:
        print(f"[-] Error checking robots.txt: {e}")
        return True  # Default to allowing crawl if there's an error.  Err on the side of caution.



def extract_emails(url, include_hidden=False, visited_urls=None):
    """
    Extracts email addresses from a website, including linked pages.

    Args:
        url (str): The URL of the website to scrape.
        include_hidden (bool, optional): Whether to include emails from hidden fields. Defaults to False.
        visited_urls (set, optional): A set of URLs already visited to avoid loops.
            Defaults to None, in which case a new set is created.

    Returns:
        set: A set of unique email addresses found on the website and linked pages.
    """
    emails = set()
    if visited_urls is None:
        visited_urls = set()

    if url in visited_urls:
        return emails  # Avoid infinite recursion

    visited_urls.add(url)  # Mark this URL as visited
    print(f"[*] Extracting emails from {url}...")

    try:
        response = requests.get(url, timeout=10, verify=False)  # Add verify=False here
        response.raise_for_status()  # Raise an exception for bad status codes
        soup = BeautifulSoup(response.text, 'html.parser')

        # 1. Find emails in visible text (more lenient regex)
        for text in soup.find_all(text=True):
            found_emails = re.findall(r"[\w\.-]+@[\w\.-]+", text)  # Relaxed regex
            emails.update(found_emails)

        if include_hidden:
            # 2. Find emails in hidden input fields
            for input_tag in soup.find_all('input', type='hidden'):
                if 'value' in input_tag.attrs:
                    found_emails = re.findall(r"[\w\.-]+@[\w\.-]+", input_tag['value'])
                    emails.update(found_emails)

        # 3. Find emails in href attributes of mailto links
        for a_tag in soup.find_all('a', href=re.compile(r"^mailto:")):
            href = a_tag['href']
            email_match = re.search(r"mailto:([\w\.-]+@[\w\.-]+)", href)
            if email_match:
                emails.add(email_match.group(1))

        # 4. Follow links on the same domain (recursive)
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            absolute_url = urljoin(url, href)  # Convert relative URLs to absolute
            parsed_current_url = urlparse(url)
            parsed_new_url = urlparse(absolute_url)

            # Check if the link is on the same domain
            if parsed_current_url.netloc == parsed_new_url.netloc:
                if can_crawl(absolute_url):
                    emails.update(extract_emails(absolute_url, include_hidden, visited_urls))
                else:
                    print(f"[-] Skipping {absolute_url} due to robots.txt")

    except requests.exceptions.RequestException as e:
        print(f"[-] Error fetching or parsing {url}: {e}")
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")
    return emails



def main():
    """
    Main function to drive the email extraction process.
    """
    parser = argparse.ArgumentParser(description="Extract email addresses from a website.")
    parser.add_argument("url", type=str, help="The URL of the website to scrape.")
    parser.add_argument(
        "-r", "--respect-robots", action="store_true", help="Respect the website's robots.txt file."
    )
    parser.add_argument(
        "-i", "--include-hidden", action="store_true", help="Include emails from hidden input fields (less reliable)."
    )
    parser.add_argument(
        "-f", "--follow-links", action="store_true", help="Follow links on the same domain."
    )
    args = parser.parse_args()
    target_url = args.url
    respect_robots = args.respect_robots
    include_hidden = args.include_hidden
    follow_links = args.follow_links

    # Validate the URL
    try:
        result = urllib.parse.urlparse(target_url)
        if not all([result.scheme, result.netloc]):
            raise ValueError("Invalid URL")
        # Check that the scheme is http or https
        if result.scheme not in ['http', 'https']:
            raise ValueError("URL scheme must be http or https")
        host = result.netloc
        try:
            socket.gethostbyname(host)  # Check DNS resolution
        except socket.gaierror:
            print("[-] Invalid URL: Hostname cannot be resolved.")
            sys.exit(1)

    except ValueError:
        print("[-] Invalid URL format. Please include http:// or https://")
        sys.exit(1)

    if respect_robots:
        if not can_crawl(target_url):
            print(f"[-] Crawling {target_url} is disallowed by robots.txt.")
            sys.exit(1)
        else:
            print("[+] Crawling is allowed by robots.txt")

    print(f"[*] Scraping email addresses from {target_url}...")
    emails = extract_emails(target_url, include_hidden) if not follow_links else extract_emails(target_url, include_hidden)

    if emails:
        print("[+] Found the following email addresses:")
        for email in emails:
            print(email)
    else:
        print("[-] No email addresses found on the website.")
    print("[*] Done!")
