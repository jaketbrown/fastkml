#!/usr/bin/env python3
import atheris
import sys
import datetime

from dateutil.tz import tzoffset
from dateutil.tz import tzutc

with atheris.instrument_imports(include=['aicsimageio']):
    import fastkml as kml
    from fastkml.enums import DateTimeResolution
    from fastkml.times import KmlDateTime

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    if len(data) == 0:
        return 0
    year = fdp.ConsumeIntInRange(1900, 2023)
    day = fdp.ConsumeIntInRange(1, 28)
    month = fdp.ConsumeIntInRange(1, 12)
    try:
        dt = datetime.datetime(year=year, day=day, month=month)
        kdt = KmlDateTime(dt, DateTimeResolution.year)
    except Exception:
        return

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
