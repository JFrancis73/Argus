import sys
import os
from selenium import webdriver
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

def take_screenshot(url, output_dir, file_name, geckodriver_path):
    options = Options()
    options.headless = True
    service = FirefoxService(executable_path=geckodriver_path)
    driver = None
    try:
        driver = webdriver.Firefox(service=service, options=options)
        driver.get(url)
        
        # Wait for the page to load completely
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located(('tag name', 'body'))
        )
        time.sleep(5)
        screenshot_path = os.path.join(output_dir, file_name)
        driver.save_screenshot(screenshot_path)
        # print(f"Screenshot saved to {screenshot_path}")
    except Exception as e:
        print(f"[!] Failed to take screenshot for {url}: {e}")
    finally:
        if driver:
            driver.quit()

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python scraper.py <url> <output_dir> <file_name> <geckodriver_path>")
        sys.exit(1)

    url = sys.argv[1]
    output_dir = sys.argv[2]
    file_name = sys.argv[3]
    geckodriver_path = sys.argv[4]

    take_screenshot(url, output_dir, file_name, geckodriver_path)
